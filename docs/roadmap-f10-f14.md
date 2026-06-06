# Roadmap: F10 (Prometheus metrics), F15 (RBAC), F14 (Sidecar UI)

Captured for later. These are planned but **not yet implemented**. Sequencing:
**F10 → F15 → F14** (each independently shippable; F10 stands alone, F15 is a
security win on its own and the UI's prerequisite, F14 consumes both).

## Decisions locked (from review discussion)
- **F10 endpoint:** repurpose `GET /metrics` to Prometheus exposition
  (unauthenticated, NetworkPolicy-restricted); move the existing protected JSON
  to `GET /metrics/summary`.
- **F10 implementation:** use the `prometheus-client` library.
- **F14 admin auth:** role-based scopes (RBAC) — see F15.
- **F14 logs source:** the UI queries the existing log store (Loki/Splunk);
  the gateway is unchanged for logs (structured JSON + correlation IDs already exist).

---

## F10 — Prometheus metrics

**Deps:** add `prometheus-client`; regenerate `requirements.txt`.

**New `device_mcp_gateway/metrics.py`** (module-level registry + instruments):
- `mcp_http_requests_total{method,path,status}` + `mcp_http_request_duration_seconds{method,path}` (histogram) — from the `log_requests` middleware.
- `mcp_tool_calls_total{hostname,method,status}` + `mcp_tool_call_duration_seconds{hostname}` — from the audit dispatch points.
- Gauges `mcp_registered_devices`, `mcp_active_pods`, `mcp_reachable_devices` — refreshed by a periodic async task started in lifespan (Prometheus collection is sync; `list_devices()` is async).
- `mcp_active_sse_connections` — inc/dec in the SSE generator (per-replica; Prometheus aggregates).

**`main.py`:**
- `GET /metrics` → unauthenticated Prometheus exposition (`generate_latest()`, `CONTENT_TYPE_LATEST`), moved beside `/health`.
- Move current JSON to `GET /metrics/summary` (stays under the `protected` router).
- Wire middleware/dispatch/SSE instrumentation; start/stop gauge-refresh task in lifespan.

**Worker metrics (distributed, possible phase 2):** workers have no HTTP server —
add `prometheus_client.start_http_server(metrics.worker_port)` in `worker_main`
exposing worker-side tool-call durations / pod counts; also unlocks the
**redis-stream-lag** signal the worker HPA stub (`deploy/kubernetes/hpa.yaml`) wants.

**Deploy/docs:** Prometheus scrape annotations on gateway Service/Deployment;
`ServiceMonitor` example; note `/metrics` is unauthenticated on the API port
(NetworkPolicy already restricts who reaches `:8000`; stricter isolation = the
rejected "separate port" option). Update README API table + `docs/observability.md`
with metric names/labels/scrape config + a Grafana starter.

**Tests:** `/metrics` 200 text/plain with expected names; counter increments after
a request; `/metrics` unauthenticated while `/metrics/summary` requires auth;
gauge refresher reflects device counts.

---

## F15 — RBAC auth scopes (UI enabler; security win on its own)

Today: one gateway API key for everything. Add roles without breaking single-key setups.

**Token model (recommended):** scoped **static API keys** (key→role) behind a clean
`resolve_role(credentials)` seam that can later swap to JWT/OIDC. *(Open
sub-decision: scoped static keys now vs JWT/OIDC now — PyJWT is already a dependency.)*
- Roles: `viewer` (all GET / read, `/metrics/summary`), `admin` (device POST/PUT/DELETE).
- Config: `gateway.rbac` (key→role) or `MCP_ADMIN_KEY`/`MCP_VIEWER_KEY`.
- **Back-compat:** only `MCP_GATEWAY_API_KEY` set → maps to `admin` (today's behavior);
  no key → auth disabled (unchanged).

**`main.py`:** `require_auth` resolves role onto `request.state`; `require_role("admin")`
dependency on mutation routes, `require_role("viewer")` (any authed) on reads; add
`role` to audit log fields.

**Tests:** viewer GET ok / 403 on POST/DELETE; admin both; legacy single-key = admin;
auth-disabled unchanged.

---

## F14 — Sidecar UI (separate repo / deployment)

Lives outside this repo (e.g. `device-mcp-gateway-ui`). Gateway gains only small enablers.

**Gateway-side (small):**
- CORS: configure `cors.allowed_origins` for the UI origin (already supported).
- REST surface already covers device CRUD + tools; F10 adds metrics; F15 adds safe mutations.
- Optional `/admin/overview` aggregate to cut UI round-trips.
- Logs: none — UI queries the log store directly.

**UI architecture (recommended): thin BFF + SPA.**
- **BFF (backend-for-frontend):** small server-side component holds the gateway
  admin credential (never in the browser), exposes a browser session, proxies to
  the gateway API / Prometheus query API / Loki. RBAC session handling lives here.
- **Phasing:** (1) device management over REST + status; (2) monitoring — embed
  Grafana panels or render from the Prometheus query API, logs via Loki/Splunk
  query API; (3) live updates (SSE/WS) + RBAC-aware views.
- **Deploy:** own Deployment/Service/Ingress + NetworkPolicy (egress to gateway
  API, Prometheus, log store). No coupling to the gateway chart beyond reachability.

**Open sub-decision:** scaffold a starter `device-mcp-gateway-ui` (BFF + minimal
device screens) vs just deliver the API/OpenAPI contract and leave the build.

---

## Open sub-decisions to resolve before starting
1. RBAC token type: scoped static keys (default) vs JWT/OIDC now.
2. UI scaffolding: scaffold a starter repo vs API contract only.
3. Worker metrics: include in F10 now vs land gateway endpoint first, worker as fast follow.

**Suggested start:** F10 (self-contained, unblocks Grafana + UI monitoring).
