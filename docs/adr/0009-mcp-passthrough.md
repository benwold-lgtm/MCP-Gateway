# ADR-0009: MCP passthrough — a remote MCP server is a device, not a second entity

- **Status:** Accepted
- **Date:** 2026-08-06
- **Related findings:** F-04, F-08, F-09, F-25, F-26, F-28, F-41, F-43
- **Amends:** [ADR-0004](0004-single-tenant-per-stack.md) (the cost register below is the
  entity-model half of that decision), [ADR-0008](0008-fleet-sessions.md) (proxied tools
  take part in fleet sessions unchanged)

## Context

Until now the gateway had exactly one way to acquire tools: translate an OpenAPI document.
Federating an **existing MCP server** — a remote server that already speaks the protocol —
needs no translation at all. Its tools arrive fully formed from `tools/list`, and a call is
forwarded rather than synthesised.

The structural question was not how to speak the protocol. It was **what a remote MCP server
*is*** in this system. Two answers were available:

1. a second first-class entity, with its own registry keys, table, routes and metrics; or
2. a `DeviceConfig` with a discriminator field.

That choice is load-bearing well beyond this feature, because the thing that would make a
future in-app tenancy retrofit expensive is the **flat `hostname` namespace**: ~20 Redis key
shapes, the SQLite primary key, the `/v1/devices/{hostname}` route family, client-visible
`device://{hostname}` URIs, the consumer-group name, and every per-device metric label. A
second flat-keyed entity would mean threading a future `tenant` dimension through *two* sets
of all of those instead of one.

A second force: the gateway's safety properties live in the translator and the pod. A proxied
tool bypasses the translator entirely, so any protection implemented there is silently absent
on the new path unless it is deliberately re-applied.

## Decision

**A remote MCP server is a device.** `DeviceConfig` gains two discriminator fields —
`upstream_kind` (`"openapi" | "mcp"`, what the upstream *speaks*) and `upstream_transport`
(`"http" | "sse"`, how we *talk* to it) — and reuses `base_url`, which is already
SSRF-validated on register and update.

Four specifics follow:

- **`transport` is not overloaded.** It is *inbound* — how the pod serves MCP to clients —
  and a proxied device keeps `transport="sse"`. Outbound direction is the new
  `upstream_transport`. Registration rejects the two being confused.
- **The manifest carries a `source` discriminator**, not a second manifest type. `McpTool`
  gains `source` (`"openapi" | "proxy"`) and a sibling `ProxyToolSpec` holding the upstream
  tool name. Readers branch on `source`, **never** on `method == ""`.
- **Dispatch is a sibling pod over a shared base.** `BasePod` holds lifecycle, the guarded
  client, token bucket, breaker and the JSON-RPC router, with one abstract
  `_dispatch_tool_call`. `McpProxyPod` implements the same public surface as `DevicePod`, so
  every existing caller works untouched.
- **v1 proxies tools only.** No resources, no prompts, no stdio upstreams, and
  `upstream_transport="sse"` is accepted in the schema but refused at registration.

**Naming debt is accepted.** "Device" becomes a slight misnomer. `DeviceConfig`, `DevicePod`
and `/v1/devices` are **not** renamed: whole-repo churn, zero functional value, and it would
break the UI's generated types.

## Consequences

- **Positive — the freshness and governance stack comes for free.** `record_tool_change`,
  `tools_revision`, `GET /devices/{h}/tools/diff`, `mcp_device_tools_changed_total` and the
  breaking-change alert all key on `hostname`, so they cover proxied upstreams with no new
  code. This matters more here than for OpenAPI: a static document cannot change its own
  tools, but a live MCP server can — see [threat-model.md](../threat-model.md) B5.
- **Positive — fleet sessions, RBAC, rate limiting, admission control, dead-lettering, the
  idempotency guard and audit apply unchanged**, because they operate on devices.
- **Negative — protections that live in the translator had to be re-applied by hand**, and
  are therefore a standing regression risk on this path: `_sanitize_text` (F-26) over every
  upstream tool name and description, and the operation-count cap (F-09) as a tool-count and
  payload-byte cap. Both are tested at parity with the OpenAPI path.
- **Negative — two spec-fetch paths now branch on upstream kind.** `DeviceWorker._fetch_spec`
  and `WorkerHealthLoop._fetch_spec` are deliberately different methods (one probes discovery
  paths concurrently, the other polls serially). Teaching one and not the other produced a
  device that registered, reported reachable, and never spawned a pod — found on a cluster,
  not in the suite.
- **Idempotency is decided, not inherited.** `is_idempotent_call` returns `False` for
  `source="proxy"` rather than reading a backing HTTP method that a proxied tool does not
  have. An absent method already happened to evaluate as non-idempotent, so the behaviour was
  correct *by accident*; the explicit branch makes it correct *by decision*, so a redelivered
  stream message cannot re-execute a proxied write (F-08, [ADR-0005](0005-at-least-once-with-idempotency-guard.md)).
- **Follow-ups:** resources and prompts, stdio upstreams, and SSE upstream transport are all
  deliberately unbuilt. The protocol revision this implements (`2025-06-18`) is two behind
  current; see [Protocol currency](#protocol-currency).

## Hashing: a canonical projection, not the raw response

The OpenAPI path hashes a parsed document, which is stable only because a static file parses
in a fixed order. `tools/list` ordering is **server-controlled**, so hashing the raw response
would make every poll look like a change: pod replaced every cycle, `tools_revision` inflated,
a breaking-change alert each time, fleet-wide.

Proxied upstreams therefore hash a canonical projection — sorted by tool name, with sorted
keys, over the contract fields only (`name`, `description`, `inputSchema`, `annotations`).
Reordering and extra per-response metadata are invisible; a changed description, schema or
tool set is not.

Reachability is decided the same way. `status_code < 500` scores a `405` from an MCP endpoint
as healthy, so for `upstream_kind="mcp"` reachability means **a successful handshake**, not a
non-5xx.

## Protocol currency

This implements MCP revision **`2025-06-18`** in both directions. Current is `2026-07-28`,
which removes the `initialize` handshake, `Mcp-Session-Id`, and SSE resumability, and makes
the protocol stateless per request. Those revisions are **not** mutually compatible: interop
exists only where an implementation deliberately supports both eras.

This is recorded here rather than treated as a defect of the design. The passthrough seam —
`BasePod`, one abstract `_dispatch_tool_call`, an upstream client behind a small interface —
is where a protocol uplift lands, and a stateless protocol *removes* the two hardest bugs this
feature hit (a missing handshake and a leaked session per health cycle). See
[testing-gaps.md](../testing-gaps.md) and the Phase 6 scope.

## What stays cheap if in-app tenancy is later chosen

The register the entity-model decision was made against. Passthrough as built **adds nothing**
to any row — that is the point of the single-entity choice.

| # | Decision | Cost later | Mitigation taken |
|---|----------|-----------|------------------|
| D1 | `hostname` stays the sole identity | Composite `(tenant, hostname)` PK; SQLite has no ALTER path to one; ~15 backend signatures; the route family; client-visible `device://` URIs; the consumer-group name; every metric label | `shared/keys.py` `KeyBuilder` cut the Redis/URI share from ~22 edits to 2 |
| D2 | MCP upstreams share the `hostname` namespace | **None additional** — this is the decision that prevents doubling D1/D3/D5/D6 | — |
| D3 | Global scopes; `require_scope` takes no resource | Per-resource authz needs the dependency to see a resource loaded *after* it runs — structural, ~12 handlers | Passthrough adds **zero** new handlers; a separate route family would have added ~6 |
| D4 | Outbound auth = the gateway's stored per-server credential; `apply()` stays zero-arg | **None** — strictly more tenancy-compatible than on-behalf-of, which is a token-propagation problem rather than a storage one | Recorded so it is not revisited |
| D5 | One Fernet codec for all stored credentials | Per-tenant DEKs and rotation | No second credential store for MCP upstreams |
| D6 | One Redis DB, unprefixed keys | ~20 edits, each able to orphan live control-plane data | `KeyBuilder(prefix=…)` → 1 edit |
| D7 | `device://{hostname}` URIs are client-facing | Under tenancy these leak the flat namespace or break cached URIs | v1 mints **no** proxied resource URIs, so there is no second URI shape to migrate |
| D8 | Fleet namespaces tools as `{hostname}_{tool}` | A tenant in the LLM-visible name breaks prompt caches and allowlists | Proxied tools reuse the same rule — one decision, not two |

**Deliberately not done:** no `tenant` field "just in case" — a field that is always
`"default"` and half-enforced is the F-01/F-32 bug class, and it forces the SQLite primary-key
question that cannot be answered yet.

## Alternatives considered

- **A second entity (`/v1/mcp-servers`, its own keys and table).** Rejected: it doubles every
  row of the register above, and buys only naming accuracy.
- **Subclass `DevicePod`.** Rejected: its `__init__` registers tools and builds HTTP closures,
  so a proxy subclass would inherit machinery it must then undo. Extracting `BasePod` was the
  smaller change and left `DevicePod`'s behaviour identical.
- **Use the MCP SDK's `streamablehttp_client`.** Rejected for v1: it is a task-group context
  manager that fights the worker's dispatch model, and `create_mcp_http_client` defaults to
  `follow_redirects=True` — exactly what `build_guarded_client(follow_redirects=False)`
  prevents. Reusing our guarded client keeps SSRF re-validation, address pinning, the port
  denylist and mTLS on the hot path.
- **A separate `upstream_url` field.** Rejected: a new URL field is a new place to forget
  `validate_target_url` (F-02).
