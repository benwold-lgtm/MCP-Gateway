# Phase 6 scope — Streamable HTTP inbound, then MCP `2026-07-28`

**Status:** scoped, not started. Written 2026-08-06, against spec revision `2026-07-28`.

## Why this is not optional

Two independent forces point the same way, and only one of them is about being current.

1. **Our only inbound transport is deprecated.** The gateway serves clients over
   **HTTP+SSE** — `GET /sse` returning an `endpoint` event, then `POST /messages?session_id=`.
   That transport has been deprecated since revision `2025-03-26` and is now formally
   *Deprecated* under the feature-lifecycle policy, with a removal clock. `transport != "sse"`
   is a hard reject in `api/devices.py` and `api/sse.py`: there is no alternative to fall back
   to. **We owe a Streamable HTTP inbound regardless of whether we adopt `2026-07-28`.**
2. **We speak `2025-06-18`, current is `2026-07-28`,** and the two eras do not interoperate.
   Not "degrade gracefully" — *fail*, in both directions, unless an implementation
   deliberately supports both. As upstreams move, a passthrough device pointed at a modern-only
   server stops working.

Doing these separately means paying for the transport work twice. Do the transport, then the
era, in that order — the second lands inside the first.

## What `2026-07-28` actually changes

It is the largest revision since launch, and its direction is **statelessness**: the protocol
stops owning session state so it can scale on ordinary HTTP infrastructure.

| Removed | Replaced by |
|---------|-------------|
| `initialize` / `notifications/initialized` handshake | Per-request `_meta`: `io.modelcontextprotocol/protocolVersion`, `clientCapabilities`, `clientInfo` |
| `Mcp-Session-Id` | Server-minted handles passed as ordinary tool arguments, where state is genuinely needed |
| SSE resumability (`Last-Event-ID`, event IDs) | Nothing — a broken stream loses the in-flight request; the client re-issues it with a new id |
| The HTTP `GET` endpoint, `resources/subscribe`/`unsubscribe` | `subscriptions/listen` — one long-lived POST-response stream, opted into per notification type |
| `ping`, `logging/setLevel`, `notifications/roots/list_changed` | Log level per request via `_meta`; the rest deleted |

New obligations: `server/discover` is **mandatory** for servers; every result carries
`resultType`; list results carry `ttlMs` and `cacheScope`; `Mcp-Method` / `Mcp-Name` headers
are required on POST; error codes are renumbered (`-32020`–`-32099` reserved for the spec) and
resource-not-found moves `-32002` → `-32602`.

Roots, Sampling and Logging are **Deprecated** (twelve-month minimum window). We implement
none of them, so this costs us nothing — and MRTR, which replaces server-initiated requests,
is mostly not our problem for the same reason.

## The shape of the work

### Workstream A — Streamable HTTP inbound (legacy semantics)

Serve `2025-06-18` over Streamable HTTP alongside the existing HTTP+SSE endpoints. One new
endpoint per surface (device and fleet) accepting a JSON-RPC POST and answering inline or as
an SSE-framed response body. Session state still exists here — this workstream does not change
semantics, only the transport carrying them.

This is where the distributed-mode integration work lives: a POST arriving at any gateway
replica has to wait for a worker's result and return it on *that* response, rather than
publishing it to a stream a different replica is holding open. The result plumbing already
exists (`session:{id}:results`); what changes is who is waiting on it.

### Workstream B — the modern era (dual-era)

**Inbound (we are a server).** Branch on how the client opens: modern `_meta` → stateless;
`initialize` → legacy, exactly as today. Add `server/discover`, `resultType` on every result,
cache hints on lists, the required request headers, and the renumbered errors. Advertise both
eras. Legacy clients keep working — that is the whole point of dual-era, and it is why the
existing SSE surface can stay through a deprecation window rather than being cut over.

**Outbound (we are a client).** `StreamableHttpClient` gains era detection: attempt a modern
request, inspect the body of a `400` before falling back to `initialize`, and **cache the
verdict per origin** (the spec is explicit that era is a property of the server, not a
request). Everything handshake-shaped then becomes dead code on the modern path:
`ensure_initialized`, the init lock, session tracking, the 404 re-handshake, `close_session`.

### What gets deleted, and what does not

The honest accounting, because "simpler" should be checkable:

| Deleted once legacy support is dropped | Survives untouched |
|---|---|
| Session registry, ownership, TTL, replica routing (`shared/session_router.py`, 228 lines, reaching into 6 modules) | Pods, breaker, token bucket, admission control |
| The `endpoint`-event dance in `api/sse.py` (236 lines) | Manifest, F-28 validation, F-26 sanitisation |
| Per-session fleet tool storage in `api/fleet.py` | Tool-change governance (F-41) |
| Handshake + session handling in `upstream/mcp_client.py` | Worker dispatch and result correlation — **per request instead of per session** |
| Inbound `initialize` / `notifications` / `ping` handling in `pods/pod_base.py` | The idempotency guard (F-08), which becomes *more* load-bearing |

**Net: fewer moving parts at the destination, more during the overlap** — dual-era means both
paths exist until legacy is dropped. Two bugs this codebase actually shipped (a missing
handshake; a session leaked per health cycle, ~5,760/device/day) are bugs that cannot exist in
a stateless protocol.

The SDK is not an obstacle: `FastMCP` appears exactly once, for a server name and an
instructions string. Our own JSON-RPC router does the work, so the `mcp` 1.x → 2.x pin is
close to free.

## Decisions needed before starting

1. **`x-mcp-header` (SEP-2243).** The spec now blesses deriving HTTP headers from tool
   parameters — precisely what F-25 forbids and what we have a test asserting is impossible.
   Options: don't implement it (spec-incomplete, safest); implement with a strict allowlist and
   reserved headers unreachable (recommended); implement as specified (rejected — it hands an
   LLM-controlled string a header slot on an authenticated outbound call).
2. **How long HTTP+SSE inbound stays.** Dual-era makes keeping it cheap; keeping it forever
   makes the deletion column above hypothetical. Suggest: one minor release after Streamable
   HTTP inbound ships, announced in the CHANGELOG.
3. **The supported-version set we advertise**, which is what `server/discover` and
   `UnsupportedProtocolVersionError` report. Suggest `2026-07-28` + `2025-06-18`, dropping the
   two older revisions we currently list but have never tested against.
4. **Whether passthrough gains `subscriptions/listen`.** We advertise
   `tools.listChanged: false` honestly today and poll instead. Staying with polling is
   defensible — governance is a *diff*, not a notification — but a modern upstream may expect
   the option.

## Traps, from what this codebase has already taught us

1. **Test against an implementation nobody here wrote.** The stateless-upstream bug in Phase 3
   survived a full suite because every stub was stateless too: the tests agreed with the
   implementation instead of checking it. The official SDK's server *and* client are the
   reference for both directions.
2. **Test the cold path.** Two of this feature's three real defects were on paths the tests
   skipped because a fixture pre-seeded state (a cached manifest; an already-set `spec_hash`).
   For Phase 6 that means: a first request from a client whose era is unknown, and an upstream
   whose era has never been probed.
3. **Era detection is per origin and must be cached** — and the cache must be invalidated when
   the assumption fails, or a server upgrading mid-flight wedges every device pointed at it.
4. **`resultType` is required on *every* result.** Missing it on one rarely-taken branch is a
   protocol violation a modern client may reject; grep the router for every `return` that
   builds a result, not just the common ones.
5. **The renumbered error codes are covered by `error-catalog.md`,** which a test keeps in sync
   — the doc must move with the code or the suite goes red.

## Verification

- The official MCP SDK's server and client at both eras, exercised in all four
  client/server-era combinations, with the two "Fails" cells asserted to fail *cleanly* and
  with an actionable message — not to hang.
- On the cluster, distributed mode, mixed fleet: an OpenAPI device and a proxied MCP device
  reached by a modern client and a legacy client at the same time.
- The existing suite must stay green throughout: dual-era means today's clients keep working,
  and any regression there is the feature failing at its stated purpose.

## Sizing

Larger than MCP passthrough was. Workstream A is a contained transport addition. Workstream B
touches the inbound router, the upstream client, the session layer and the error catalogue at
once, and its cost is dominated by supporting **two eras concurrently** rather than by either
era alone. Deletion of the legacy path is a later, separate, satisfying commit.
