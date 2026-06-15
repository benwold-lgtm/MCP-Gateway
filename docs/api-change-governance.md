# API change governance

How the gateway handles two facts about the upstream APIs it fronts: their
**OpenAPI specs change over time** (F-41), and OpenAPI describes more than the
request/response `paths` the gateway translates (F-46).

---

## Tool-set change governance (F-41)

A device's MCP tool set is **generated from its upstream OpenAPI spec**. The
gateway re-fetches the spec on a schedule (and on registration); when the spec
hash changes it re-pods the device and regenerates the tool set. That means the
tools a live MCP client sees can change underneath it — a tool can disappear, a
parameter can become required, an HTTP method can change. Without governance
that mutation is silent: a client keeps calling the old shape and starts
failing with no signal as to why.

The gateway turns every spec-driven tool-set mutation into a recorded, classified
signal.

### What is recorded

On each tool-set change the gateway computes a diff between the old and new tool
sets and classifies it:

| Class | Meaning | Examples |
|-------|---------|----------|
| **compatible** | A client calling the old shape still works | tool added; optional parameter added; a parameter that was required is now optional; description changed |
| **breaking** | A previously-valid call can now be rejected | tool removed; parameter removed; parameter newly required; HTTP method changed |

The change is recorded three ways:

1. **Audit event** — `event="audit"`, `action="device.tools_changed"`,
   `outcome="breaking"` or `"compatible"`, with `added` / `removed` / `changed`
   tool names, the `breaking` flag, and human-readable `reasons`. It rides the
   tamper-evident audit stream (see [audit-logging.md](audit-logging.md)), so a
   breaking change is attributable and non-repudiable.
2. **Metric** — `mcp_device_tools_changed_total{hostname, breaking}` (Prometheus
   counter). A sustained `breaking="true"` rate means upstream APIs are changing
   under live clients — alertable (see [observability.md](observability.md)).
3. **Log** — a `WARNING` for a breaking change (naming the reasons), `INFO`
   otherwise.

### The client-facing signal: `tools_revision`

Each device carries a monotonic **`tools_revision`** counter, bumped once per
tool-set change (compatible or breaking). It is exposed on:

- `GET /v1/devices/{hostname}` — `DeviceDetail.tools_revision`
- `GET /v1/devices/{hostname}/diagnostics` — `DeviceDiagnostics.tools_revision`

A client (or a UI) detects "the tools moved under me" by polling one of those
and comparing `tools_revision` to the value it last saw; on a bump it re-issues
`tools/list`. A no-op spec edit (hash changed but the generated tool set is
identical) does **not** bump the revision — only a real tool-set change does.

### Why not a real-time `notifications/tools/list_changed` push?

The MCP layer advertises `tools.listChanged: false` in its `initialize`
response — honestly. The SSE connection is replica-pinned (see F-20), and on a
pod replace the old pod's transport is torn down, so the client's stream drops
and it reconnects + re-lists anyway. Rather than fake a push capability we
cannot reliably deliver across the distributed boundary, the governance signal
is the **recorded, classified change** plus the **pollable revision**. A future
inbound-notification bridge (see F-46 below) is the natural place a true push
would land.

### Operator guidance

- Alert on `rate(mcp_device_tools_changed_total{breaking="true"}[1h]) > 0` to
  catch upstreams breaking their contract under live clients.
- Forward the `device.tools_changed` audit records to your SIEM for a change log
  of every device's tool surface over time.
- Pin a flaky upstream by registering it against a **versioned spec URL**
  (e.g. `/v3/openapi.json`) so a vendor's `/openapi.json` rev doesn't silently
  re-pod it.

---

## Webhooks & callbacks are out of scope — the gateway is pull-only (F-46)

The translator generates MCP tools from a spec's request/response **`paths`**
only. Two OpenAPI constructs that describe **server-initiated** delivery are
deliberately **not** translated:

- **`webhooks`** (OpenAPI 3.1) — operations the upstream *calls on a registered
  receiver* when an event occurs.
- per-operation **`callbacks`** (OpenAPI 3.0/3.1) — out-of-band requests the
  upstream makes back to the caller after an operation (async completion,
  subscriptions).

### Why

The gateway is a **pull-only** request/response bridge: an MCP client invokes a
tool → the gateway calls the upstream → the response is returned. There is no
inbound HTTP surface on which an upstream could deliver an event, and MCP's
`tools/call` is request/response, not a subscription. Translating `webhooks` /
`callbacks` into tools would produce tools that can never be invoked
meaningfully, so they are omitted rather than surfaced as dead entries.

### Implications for integrators

- An API whose primary integration model is "register a webhook and receive
  push events" is **only partially usable** through the gateway: its synchronous
  `paths` work as tools; its event-push half does not.
- If an upstream offers **both** a webhook subscription *and* a polling endpoint
  (e.g. `GET /events?since=…`), use the polling endpoint — it translates to a
  normal tool and fits the pull model. Pagination/cursor signals on such
  endpoints are surfaced on the result envelope (see
  [error-catalog.md](error-catalog.md)).
- Long-running operations that complete asynchronously are surfaced as a poll
  handle on the result envelope (F-45), not via callbacks — the client polls the
  device's status endpoint rather than the device calling back.

### Future direction

The natural extension is an **inbound webhook → MCP notification bridge**: a
gateway ingress endpoint that receives an upstream's webhook delivery,
authenticates it, and fans it out to subscribed MCP clients as a server
notification. That requires the server→client push channel the current
transport intentionally does not provide (see the F-41 note above), so it is
tracked as future work, not a current capability.
