# Roadmap: F10 (Prometheus metrics), F15 (RBAC), F14 (Sidecar UI)

Captured for later. These are planned but **not yet implemented**. Sequencing:
**F10 → F15 → F14** (each independently shippable; F10 stands alone, F15 is a
security win on its own and the UI's prerequisite, F14 consumes both).

## Decisions locked (from review discussion)
- **F10 exposition:** Prometheus metrics on a **dedicated metrics port**
  (`metrics.port`, default 9100), not on the public API port. This matches the
  worker (decision below), lets `ServiceMonitor`/NetworkPolicy target a named
  metrics port instead of opening an unauth hole in the API surface, and avoids a
  breaking rename of the existing API-port endpoint. The existing protected JSON
  stays on the API port, renamed to `GET /metrics/summary`.
- **F10 labels:** label HTTP metrics with the **route template**
  (`/devices/{hostname}`), never the concrete path — concrete paths are an
  unbounded-cardinality hazard that will OOM Prometheus.
- **F10 implementation:** use the `prometheus-client` library; **one process per
  pod** (scale via replicas) so the default registry needs no multiprocess mode.
- **F14 admin auth:** scope-based authorization (RBAC) — see F15.
- **F14 logs source:** the UI's **BFF** queries the existing log store
  (Loki/Splunk); the gateway is unchanged for logs (structured JSON + correlation
  IDs already exist). The browser never holds the log-store credential.
- **F15 auth seam:** authenticate to a **`Principal`** (`subject`, `scopes`,
  `auth_method`) and **authorize on scopes**, not a role string. Static API keys
  are the *implementation* (key→bundle-of-scopes); the `authenticate()` seam can
  later swap to JWT/OIDC without touching route call sites or the audit log.
- **F14 UI scope:** **scaffold a starter repo** (`device-mcp-gateway-ui`) — BFF +
  minimal device-management screens, generated against the gateway's published
  `/openapi.json` contract.
- **F10 worker metrics:** **included in F10** (gateway + worker together), not
  deferred — the worker runs its own `prometheus_client` HTTP server (the same
  dedicated-port pattern the gateway uses).
- **API versioning:** mount the gateway's management routes under **`/v1`** before
  the UI/BFF consumes them, and treat the auto-generated **`/openapi.json`** as the
  versioned UI contract. Adding `/v1` now is a one-line prefix; adding it after a
  consumer exists is a coordinated breaking change.

---

## F10 — Prometheus metrics

Sliced for incremental delivery:
1. **Slice 1 (gateway): ✅ DONE.** `metrics.py` + dep + dedicated metrics server +
   HTTP middleware instrumentation + device gauges + SSE gauge + `/metrics/summary`
   rename + tests.
2. **Slice 2 (worker): ✅ DONE.** worker `start_http_server` (in `worker_main`) +
   worker-side tool-call metrics (`_dispatch_call`) + redis-stream-lag gauges
   (`mcp_worker_pending_calls` / `mcp_worker_assignments_lag`) + pod gauge +
   gateway/worker scrape annotations, named metrics ports, worker metrics Service,
   NetworkPolicy ingress for `:9100`, HPA comment refresh + tests.
3. **Slice 3 (docs/deploy): ✅ DONE.** `observability.md` Prometheus section (exposition
   model, full metric reference, plain-Prometheus + ServiceMonitor scrape config, Grafana
   PromQL starters, prometheus-adapter/KEDA note) + README metrics section.

**F10 complete. F15 complete. F14 scaffold complete** (`device-mcp-gateway-ui` repo).
All three roadmap items delivered. Remaining work is incremental UI phases (monitoring,
logs, live updates) tracked in that repo's README.

**Deps:** add `prometheus-client`; regenerate `requirements.txt`.

**New `device_mcp_gateway/metrics.py`** (module-level default registry + instruments):
- `mcp_http_requests_total{method,route,status}` + `mcp_http_request_duration_seconds{method,route}` (histogram) — from the `log_requests` middleware, labelled with the **route template** via an endpoint→`path_format` map (Starlette 1.2 does not expose `scope["route"]`; unmatched paths → `__unmatched__`).
- `mcp_tool_calls_total{hostname,method,status}` + `mcp_tool_call_duration_seconds{hostname}` — instrumented where calls **execute** (embedded gateway dispatch + worker, slice 2), not where they are merely enqueued.
- Gauges `mcp_registered_devices`, `mcp_active_pods`, `mcp_reachable_devices` — refreshed by a periodic async task started in lifespan (Prometheus collection is sync; `list_devices()` is async).
- `mcp_active_sse_connections` — inc/dec in the SSE generator (per-replica; Prometheus aggregates).
- `start_metrics_server(port)` — wraps `prometheus_client.start_http_server`, tolerant of "address in use" (so the test suite, which builds many apps, never crashes on it).

**`main.py`:**
- Dedicated metrics port: `start_metrics_server(metrics.port)` in lifespan (guarded by `metrics.enabled`, default true). No `/metrics` route is added to the API app.
- Rename current JSON endpoint `GET /metrics` → `GET /metrics/summary` (stays under the `protected` router; F15 scope-gates it to `metrics:read`).
- Wire middleware/SSE instrumentation; start/stop the gauge-refresh task in lifespan.

**Worker metrics (distributed — included in F10, slice 2):** workers have no HTTP
server — add `prometheus_client.start_http_server(metrics.port)` in `worker_main`
exposing worker-side tool-call durations / pod counts; also unlocks the
**redis-stream-lag** signal the worker HPA stub (`deploy/kubernetes/hpa.yaml`) wants.
Add a worker Service + scrape annotations in `deploy/kubernetes`.

**Deploy/docs (slice 3):** dedicated metrics port on gateway + worker Services;
`ServiceMonitor` targeting the named `metrics` port; NetworkPolicy allows the
Prometheus namespace to reach `:9100` only. Update README API table +
`docs/observability.md` with metric names/labels/scrape config + a Grafana starter.

**Tests (slice 1):** `generate_latest()` contains the expected metric names; the
request counter increments (delta) after a TestClient call and is labelled with the
route **template** not the concrete path; `/metrics/summary` requires auth and
returns the JSON; the gauge refresher reflects device counts.

---

## F15 — RBAC via a Principal/scopes seam (UI enabler; security win on its own) — ✅ DONE

**Implemented** in `device_mcp_gateway/rbac.py`: `Principal{subject, scopes, auth_method}`,
`Authenticator` over static API keys, `build_authenticator(cfg)`, `authenticate_request`
(router dep) + `require_scope(scope)` (route dep). Routes gated on `devices:read` /
`devices:write` / `tools:call` / `metrics:read`; audit logs now carry `subject`.
Back-compat: legacy single key = admin; no keys = auth disabled (anonymous, full access).
Swapping to JWT/OIDC changes only `Authenticator`/`authenticate_request`.

Today: one gateway API key for everything, and auth resolves to a stringly-typed
`request.state.auth_caller`. Add scope-based authz without breaking single-key setups,
and shape the seam so a later JWT/OIDC swap touches **only** `authenticate()`.

**Seam (decided):** authenticate to a `Principal`, authorize on **scopes**.
```python
@dataclass(frozen=True)
class Principal:
    subject: str               # "key:ops-dashboard" now; OIDC "sub" later
    scopes: frozenset[str]     # {"devices:read", "devices:write", "metrics:read"}
    auth_method: str           # "api_key" | "jwt" | "none"

def authenticate(request, credentials) -> Principal   # replaces require_auth's body
def require_scope(scope: str)                          # FastAPI dependency factory
```
- **Scopes** (fine-grained, future-proof): `devices:read`, `devices:write`,
  `tools:call`, `metrics:read`. **Roles are bundles of scopes** defined in config —
  `viewer = {devices:read, metrics:read}`, `admin = all`.
- **Implementation:** scoped **static API keys** (key→role→scopes). Config
  `gateway.rbac` (key→role) or `MCP_ADMIN_KEY`/`MCP_VIEWER_KEY`.
- **Back-compat:** only `MCP_GATEWAY_API_KEY` set → an `admin` Principal (all scopes,
  today's behaviour); no key → an unauthenticated Principal with all scopes (auth
  disabled, unchanged).

**`main.py`:** `authenticate()` sets `request.state.principal`; mutation routes depend
on `require_scope("devices:write")`, reads on `require_scope("devices:read")`,
`/metrics/summary` on `require_scope("metrics:read")`. Replace the audit `caller`
field with `principal.subject` (real identity for the audit trail — the whole point
when humans act through the UI).

**Tests:** viewer scope GET ok / 403 on POST/DELETE; admin both; legacy single-key =
all scopes; auth-disabled unchanged; audit log carries `subject`.

---

## F14 — Sidecar UI (separate repo / deployment) — ✅ DONE (scaffold)

**Scaffolded** as a separate repo `device-mcp-gateway-ui` (sibling dir): FastAPI **BFF**
(session auth, role gating, gateway/Prometheus/Loki proxy) + React/Vite/TS **SPA**
(login, device list, admin register/remove), Dockerfiles, K8s manifests (own namespace,
Deployments/Services/Ingress, NetworkPolicies), docker-compose, README. Gateway-side
enabler added here: `GET /admin/overview` (aggregate fleet snapshot, `devices:read`).
BFF tests pass; SPA typechecks in a Node env (no Node toolchain on the build host).

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

**Decided:** scaffold a starter `device-mcp-gateway-ui` repo (BFF + minimal
device-management screens) to build on.

---

## Resolved decisions
1. Auth seam → authenticate to a **`Principal` + scopes**; static API keys are the
   swappable implementation (JWT/OIDC later changes only `authenticate()`).
2. RBAC token type → **scoped static API keys** (key→role→scopes).
3. UI scaffolding → **scaffold a starter repo** (BFF + minimal device screens),
   generated against the gateway's `/openapi.json`.
4. Worker metrics → **included in F10** (gateway + worker together).
5. Metrics exposition → **dedicated metrics port** (gateway + worker), route-template
   labels, one process per pod.
6. API surface → **`/v1` prefix** + `/openapi.json` as the versioned UI contract.

**Start with F10** (self-contained, unblocks Grafana + UI monitoring), then F15, then F14.

> **Long-term-seam rationale (2026-06-06 review):** the two changes from the original
> plan — Principal/scopes instead of a role string, and a dedicated metrics port with
> route-template labels — are equal cost to build today but avoid a call-site rip-out
> (auth) and a Prometheus-OOM rewrite (labels) later. `/v1` + `/openapi.json` are
> cheap now, breaking-change later.
