# Device MCP Gateway

A universal bridge that converts any OpenAPI-documented device or service into an [MCP](https://modelcontextprotocol.io/) tool server. Register a device by URL, the gateway auto-discovers its OpenAPI spec, translates every operation into an MCP tool, and serves it over SSE — ready for LLM clients (Claude Desktop, Cursor, custom agents) to invoke.

## Architecture

The gateway supports two modes selected by `registry.mode` in `config.yaml`.

### Distributed mode (production)

```
LLM clients
    │  SSE (GET /v1/devices/{hostname}/sse)
    ▼
┌───────────────────────────────────────────────────┐
│  Gateway (stateless, scale N replicas)            │
│  FastAPI  •  rate limiter  •  SSE pub/sub relay   │
└──────────────────┬────────────────────────────────┘
                   │ Redis Streams / pub/sub
┌──────────────────▼────────────────────────────────┐
│  Redis                                            │
│  device registry  •  assignments  •  tool calls   │
└──────────────────┬────────────────────────────────┘
                   │
┌──────────────────▼────────────────────────────────┐
│  Workers (stateful, scale M replicas)             │
│  DevicePods  •  health loop  •  call consumers    │
└──────────────────┬────────────────────────────────┘
                   │ httpx  (+ circuit breaker)
                   ▼
             Device APIs
```

Gateway instances are stateless — they read from Redis and relay SSE events via Redis pub/sub. Workers own the DevicePods and execute tool calls. All three components scale independently.

### Embedded mode (local development)

```
LLM client → FastAPI → Registry → DevicePod → Device API
                                └── SQLite (device registrations)
```

Single process, no Redis. Set `registry.mode: "embedded"` (the default).

---

## Requirements

- Python ≥ 3.10 (3.12 recommended; used in the Docker image)
- Redis ≥ 7 for distributed mode

---

## Quick Start (embedded mode)

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 2. Install
pip install -e ".[dev]"

# 3. Start the gateway (embedded mode; no Redis required)
device-mcp
# Override without editing config.yaml:
# device-mcp --host 0.0.0.0 --port 8000 --config /path/to/config.yaml

# 4. Register a device
curl -X POST http://localhost:8000/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"hostname": "my-sensor", "base_url": "http://192.168.1.42", "transport": "sse"}'

# 5. Connect an MCP client (see MCP Client Integration below)
```

> **Registering a device on a private/LAN address?** By default the gateway refuses
> targets that resolve to private, loopback, or link-local addresses (the Tier-0 SSRF
> guard — see [`security.allow_private_targets`](config.yaml)), so a `base_url` like the
> `192.168.1.42` above returns `400` until you opt in. For a trusted device fleet on
> private addresses, start with `MCP_ALLOW_PRIVATE_TARGETS=true` (or set
> `security.allow_private_targets: true`). Leave it off when devices are reachable over
> public DNS/addresses.

## Quick Start (distributed mode)

```bash
# 1. Start Redis, gateway, and worker via Docker Compose
MCP_GATEWAY_API_KEY=<token> MCP_SECRET_KEY=<fernet-key> docker compose up -d

# Generate a Fernet key:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 2. Scale workers (the gateway publishes a fixed host port, so scale it via
#    Kubernetes or a load balancer — see Kubernetes Deployment below)
docker compose up -d --scale worker=2

# 3. Register a device (any gateway instance)
curl -X POST http://localhost:8000/v1/devices \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "my-sensor", "base_url": "http://192.168.1.42", "transport": "sse"}'
```

---

## MCP Client Integration

### Claude Desktop

Add the device's SSE endpoint to your Claude Desktop config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "my-sensor": {
      "type": "sse",
      "url": "http://localhost:8000/v1/devices/my-sensor/sse"
    }
  }
}
```

Restart Claude Desktop after saving. The device's tools will appear in the tool picker.

### Manual invocation (SSE transport)

The SSE transport uses a two-step protocol. The server assigns a session ID — do not supply your own.

**Step 1 — Open the event stream:**
```bash
curl -N -H "Authorization: Bearer <api-key>" \
  http://localhost:8000/v1/devices/my-sensor/sse
```

The first event is `endpoint` and its `data` is the POST URL for this session:
```
event: endpoint
data: /v1/devices/my-sensor/messages?session_id=<server-assigned-uuid>
```

**Step 2 — Send a tool invocation on that session:**
```bash
curl -X POST "http://localhost:8000/v1/devices/my-sensor/messages?session_id=<uuid-from-step-1>" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
       "params": {"name": "get_readings", "arguments": {"sensor_id": 1}}}'
```

The response arrives as a `message` event on the open SSE stream, not in the HTTP response body.

---

## API Reference

All endpoints except `/health` and `/readyz` require `Authorization: Bearer <api-key>` when any API key is configured.

**Roles & scopes (RBAC).** Keys map to roles, and routes authorize on scopes:

| Role | Scopes | Can |
|------|--------|-----|
| `admin` | `devices:read`, `devices:write`, `tools:call`, `metrics:read` | everything |
| `viewer` | `devices:read`, `metrics:read` | read device state + `/v1/metrics/summary`; **no** mutations or tool calls (403) |

Configure keys via `gateway.api_key` (legacy single key = `admin`), `MCP_ADMIN_KEY` / `MCP_VIEWER_KEY`, or a `gateway.rbac` list of `{name, key, role}` (see [config.yaml](config.yaml)). If no key is set anywhere, auth is disabled (all requests permitted). The authenticated principal is recorded as `subject` in audit logs. The seam (`authenticate()` → `Principal{subject, scopes}`) is built to swap to JWT/OIDC later without touching routes.

Rate limits (per source IP): `/health` and `/readyz` — 300 req/min; `POST /v1/devices` — 60 req/min; `POST /messages` — 600 req/min. Returns 429 on excess.

> **API versioning.** The management API is served under a `/v1` prefix (e.g. `POST /v1/devices`). Operational probes (`/health`, `/readyz`) and the Prometheus scrape endpoint are intentionally **unversioned** — they are infra contracts consumed by Kubernetes and Prometheus, not application clients. A backward-incompatible change to the management API will introduce `/v2` and dual-mount `/v1` for a deprecation window.

> **Tool-set change governance & webhooks.** A device's tools are generated from its upstream OpenAPI spec, so they change when the spec changes. Every change is classified (compatible vs. **breaking**), recorded to the audit stream + a `mcp_device_tools_changed_total` metric, and surfaced to clients as a monotonic `tools_revision` on `GET /v1/devices/{hostname}` — poll it to detect a change, then `GET /v1/devices/{hostname}/tools/diff` to see *what* changed (added/removed/changed tools + the breaking flag) and re-list tools. OpenAPI `webhooks`/`callbacks` are **not** translated: the gateway is pull-only (request→response), with no inbound event surface. See [docs/api-change-governance.md](docs/api-change-governance.md) and the full mapping contract in [docs/tooling.md](docs/tooling.md).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe — process status, active pod count |
| `GET` | `/readyz` | Readiness probe — backend connectivity (Redis or SQLite) |
| `POST` | `/v1/devices` | Register a device |
| `PUT` | `/v1/devices/{hostname}` | Update a device config (replaces and restarts pod) |
| `DELETE` | `/v1/devices/{hostname}` | Unregister a device |
| `GET` | `/v1/devices` | List all registered devices |
| `GET` | `/v1/devices/{hostname}` | Get a single device's status |
| `GET` | `/v1/devices/{hostname}/tools` | List a device's MCP tools |
| `GET` | `/v1/devices/{hostname}/tools/diff` | The device's most recent tool-set change — added/removed/changed tools + breaking flag (`devices:read`) |
| `GET` | `/v1/devices/{hostname}/diagnostics` | "Why is my device down?" — status, last check + age, spec/manifest state, spawn error, circuit breaker (`devices:read`) |
| `GET` | `/v1/devices/{hostname}/sse` | Open SSE stream (MCP transport) |
| `POST` | `/v1/devices/{hostname}/messages` | Send a JSON-RPC 2.0 message via SSE |
| `GET` | `/v1/devices/{hostname}/deadletter` | Inspect dead-lettered tool calls (distributed mode; `devices:read`) |
| `POST` | `/v1/devices/{hostname}/deadletter/replay` | Re-publish dead-lettered calls onto the call stream; optional `{"ids":[...]}` (`devices:write`) |
| `DELETE` | `/v1/devices/{hostname}/deadletter` | Drain the dead-letter queue; optional `{"ids":[...]}` (`devices:write`) |
| `GET` | `/v1/metrics/summary` | Reachability counts and per-device rate-limit state (JSON, auth-protected) |
| `GET` | `/v1/admin/overview` | Aggregate fleet counts + device list in one call (UI/BFF enabler; `devices:read`) |

Prometheus metrics are exposed separately on a **dedicated metrics port** (`metrics.port`, default `9100`) at `GET /metrics`, not on the API port — point a `ServiceMonitor`/scrape config at that port and restrict it with a NetworkPolicy. Set `metrics.enabled: false` (or `MCP_METRICS_ENABLED=0`) to disable.

### Register / update device payload

```json
{
  "hostname": "my-device",
  "base_url": "http://device.local",
  "spec_url": "http://device.local/openapi.json",
  "transport": "sse",
  "auth_type": "api_key",
  "auth": {
    "api_key": "supersecret",
    "header_name": "X-API-Key"
  },
  "rate_limit_rps": 10.0
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `hostname` | Yes (POST) | Unique identifier — letters, digits, hyphens, dots; 1–253 chars |
| `base_url` | Yes (POST) | Root URL of the device API |
| `spec_url` | No | Full URL to the OpenAPI spec; auto-discovered if omitted |
| `transport` | No | Must be `"sse"` (default) |
| `auth_type` | No | `"api_key"`, `"oauth2"`, or `"none"` |
| `auth` | Conditional | Required when `auth_type` is `api_key` or `oauth2` |
| `rate_limit_rps` | No | Max requests/second to the downstream device API |

`PUT` treats all fields except `hostname` as optional — omitted fields keep their existing values.

### Response shapes

**`GET /v1/devices/{hostname}`:**
```json
{
  "hostname": "my-sensor",
  "base_url": "http://192.168.1.42",
  "spec_url": null,
  "reachable": true,
  "pod_active": true,
  "last_check": 1717500000.0,
  "transport": "sse",
  "rate_limit_rps": null,
  "spawn_error": null
}
```

**`GET /v1/devices/{hostname}/diagnostics`:**
```json
{
  "hostname": "my-sensor",
  "mode": "embedded",
  "base_url": "http://192.168.1.42",
  "spec_url": null,
  "transport": "sse",
  "reachable": true,
  "pod_active": true,
  "worker_id": null,
  "last_check": 1717500000.0,
  "last_check_age_seconds": 12.4,
  "spec_hash": "9f3c1a2b4d5e6f70",
  "has_manifest": true,
  "tool_count": 7,
  "spawn_error": null,
  "breaker": {"available": true, "state": "closed", "fail_counter": 0, "fail_max": 5, "reset_timeout": 60, "note": null}
}
```
In distributed mode the breaker runs on the worker, so `breaker` is `{"available": false, "note": "pod runs on a worker; ..."}`.

**`POST /v1/devices` / `PUT /v1/devices/{hostname}`:**
```json
{"status": "registered", "hostname": "my-sensor", "pod_active": true, "reachable": true, "spawn_error": null}
```

**`GET /health`:**
```json
{"status": "healthy", "mode": "distributed", "active_pods": 4, "registered_devices": 5, "version": "0.1.0"}
```

**`GET /readyz`:** Returns `200 {"status": "ready", "mode": "..."}` when the backend is reachable, `503 {"status": "not ready", "reason": "..."}` when not.

---

## Authentication

### Gateway API key

Set `MCP_GATEWAY_API_KEY` (environment variable) or `gateway.api_key` in `config.yaml`. When set, all endpoints except `/health` and `/readyz` require `Authorization: Bearer <key>`. Leave empty to disable authentication (not recommended for production).

### Device authentication

#### None
```json
{"auth_type": "none"}
```

#### API Key
```json
{"auth_type": "api_key", "auth": {"api_key": "my-key", "header_name": "X-API-Key"}}
```
The key can live in a header (default), a query param, or a cookie, with an optional scheme prefix (F-43):
```json
{"auth_type": "api_key", "auth": {"api_key": "my-key", "location": "query", "name": "apikey"}}
{"auth_type": "api_key", "auth": {"api_key": "my-key", "location": "header", "name": "Authorization", "value_prefix": "Bearer "}}
{"auth_type": "api_key", "auth": {"api_key": "my-key", "location": "cookie", "name": "session"}}
```
| Field | Default | Notes |
|-------|---------|-------|
| `location` | `header` | `header`, `query`, or `cookie` |
| `name` | per-location (`X-API-Key` / `api_key` / `api_key`) | header/param/cookie name; legacy `header_name` still accepted |
| `value_prefix` | `""` | prepended to the value, e.g. `"Bearer "` |

#### OAuth2 (token endpoint)
```json
{
  "auth_type": "oauth2",
  "auth": {
    "token_endpoint": "https://auth.example.com/token",
    "client_id": "my-client",
    "client_secret": "my-secret",
    "scopes": ["read", "write"]
  }
}
```
Beyond the default `client_credentials` body flow, the following are supported (F-42):
| Field | Default | Notes |
|-------|---------|-------|
| `grant_type` | `client_credentials` | also `password` (with `username`/`password`) or `refresh_token` (with `refresh_token`) |
| `auth_style` | `request_body` | `basic` sends client id/secret as HTTP Basic to the token endpoint |
| `audience` | — | provider audience (e.g. Auth0) |
| `extra_params` | — | object merged into the token request (e.g. RFC 8707 `resource`) |

The interactive `authorization_code` grant and `jwt-bearer` assertions are intentionally **not** supported — the first needs a user redirect (impossible for an unattended gateway), the second needs per-device signing-key management.

---

## Security

The full security model — trust boundaries, adversaries, and the control addressing each
threat — is in [docs/threat-model.md](docs/threat-model.md). The sections below summarize
the key controls.

### Credential encryption

Device credentials (OAuth2 `client_secret`, API keys) are encrypted at rest with a Fernet key (`MCP_SECRET_KEY`) on **both** storage paths — the SQLite store (embedded mode) and Redis (distributed mode). The gateway and workers share the same key and the same codec, so credentials are never written in plaintext when a key is set.

**Set `MCP_SECRET_KEY` before registering any devices with credentials.**

- **Distributed mode (production):** the gateway and workers **refuse to start** without a key, because credentials would otherwise be persisted to Redis in plaintext. To override for local experiments only, set `gateway.allow_plaintext_credentials: true`.
- **Embedded mode:** without a key, credentials are stored as plaintext in SQLite and the gateway logs a startup warning.

Generate a key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Pass it as an environment variable — never store it in `config.yaml` or the Kubernetes ConfigMap:
```bash
export MCP_SECRET_KEY=<your-fernet-key>
```

### Multitenancy

The gateway is **single-tenant per stack**: it has no in-application tenant isolation. The device namespace is flat (keyed by `hostname`), RBAC scopes are global within a deployment, and co-located DevicePods share decrypted credentials in one worker process. Isolate tenants by running a **separate stack per tenant** — each with its own Redis, `MCP_SECRET_KEY`, and API keys. **Do not co-host tenants in one deployment.** See [docs/multitenancy.md](docs/multitenancy.md) for the deployment model and rules.

### Rate limiting

The gateway enforces per-IP rate limits using `slowapi`. Limits are applied per gateway instance (not distributed across replicas — a Redis-backed store is recommended for multi-replica deployments). Requests that exceed the limit receive `HTTP 429`.

### CORS

CORS headers are disabled by default. To allow browser-based clients, add your origins to `config.yaml`:
```yaml
cors:
  allowed_origins:
    - "https://my-llm-app.example.com"
```

Use `["*"]` only in development.

### Circuit breaker

Each DevicePod wraps its downstream HTTP calls in a per-device circuit breaker (opens after 5 consecutive 5xx/connection failures; resets after 60 s). A tripped breaker returns `{"error": "Device unavailable: circuit breaker open", "status_code": 503}` immediately rather than waiting 15 s for a timeout.

### Correlation IDs

Every request receives an `X-Request-Id` header (taken from the incoming request or generated as a UUID4). The ID appears in all log lines for that request chain (`rid=<id>`) and is echoed in the response `X-Request-Id` header.

### TLS

The gateway serves plain HTTP. Always run it behind a TLS-terminating proxy (nginx, Caddy, cloud load balancer) in production. The Kubernetes Ingress in `deploy/kubernetes/ingress.yaml` handles TLS termination.

---

## Configuration

All settings live in `config.yaml`. Override the file location with `MCP_CONFIG`. Most secrets should be passed as environment variables rather than stored in the file.

| Key | Default | Description |
|-----|---------|-------------|
| `gateway.api_key` | `""` | Bearer token required on protected routes. Override with `MCP_GATEWAY_API_KEY` |
| `gateway.secret_key` | `""` | **Required for credential encryption.** Fernet key. Override with `MCP_SECRET_KEY` |
| `gateway.max_body_bytes` | `1048576` | Maximum POST/PUT body size in bytes (1 MB default) |
| `server.host` | `0.0.0.0` | Bind address |
| `server.port` | `8000` | Port |
| `registry.mode` | `"embedded"` | `"embedded"` (local dev, no Redis) or `"distributed"` (production, Redis required) |
| `registry.health_check_interval` | `30` | Seconds between device reachability checks |
| `registry.spec_poll_interval` | `300` | Seconds between spec refresh checks |
| `registry.spec_cache_ttl` | `3600` | Spec cache lifetime in seconds |
| `registry.max_concurrent_pods` | `50` | Max simultaneous device pods (embedded mode only) |
| `redis.url` | `"redis://localhost:6379/0"` | Redis connection URL. Override with `MCP_REDIS_URL` |
| `redis.socket_timeout` | `5` | Redis socket timeout in seconds |
| `redis.max_connections` | `20` | Redis connection pool size per gateway instance |
| `cors.allowed_origins` | `[]` | Allowed CORS origins for browser clients. Empty = disabled |
| `auth.type` | `api_key` | Default auth type for devices (`api_key`, `oauth2`, `none`) |
| `discovery.timeout` | `10` | Spec discovery request timeout in seconds |
| `storage.db_path` | `./data/devices.db` | SQLite path (embedded mode only; use `/app/data/devices.db` in Docker) |
| `transport.default` | `sse` | Default MCP transport (`sse` is the only supported value) |
| `transport.sse.keep_alive_interval` | `15` | Seconds between SSE keepalive pings |
| `logging.level` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `logging.file` | `logs/gateway.log` | Log file path |

`discovery.spec_paths` is a list of URL paths probed for auto-discovery. See `config.yaml` for the full default list.

---

## Docker

```bash
# Build and run all three services (gateway + worker + Redis)
docker compose up -d

# Scale workers (the gateway publishes a fixed host port, so scale it via
# Kubernetes or a load balancer rather than `--scale gateway`)
docker compose up -d --scale worker=2

# Stop everything
docker compose down
```

The compose file configures:
- A named `mcp-net` bridge network (all services)
- Per-service resource limits (gateway: 512M / 1 CPU; worker: 1G / 2 CPU; Redis: 256M / 0.5 CPU)
- Redis `healthcheck` — gateway and worker wait for Redis to be ready before starting

Pass secrets as environment variables:
```bash
MCP_GATEWAY_API_KEY=<token> MCP_SECRET_KEY=<fernet-key> docker compose up -d
```

**Embedded mode in Docker:** If running `registry.mode: "embedded"`, mount a volume for the SQLite database so registrations survive restarts:
```yaml
# In docker-compose.yml, add to the gateway service:
volumes:
  - ./data:/app/data
```

---

## Kubernetes Deployment

Pre-built manifests live in [`deploy/kubernetes/`](deploy/kubernetes/). The manifests assume distributed mode (`registry.mode: "distributed"` is set in the ConfigMap).

### Cluster prerequisites

The bundled manifests assume the following are already installed in the target cluster:

| Prerequisite | Needed for | Notes |
|--------------|-----------|-------|
| **Ingress controller (ingress-nginx)** | `ingress.yaml` | Uses `ingressClassName: nginx` and `nginx.ingress.kubernetes.io/*` annotations. Swap both if you run a different controller. |
| **metrics-server** | the CPU-based HPAs (`hpa.yaml`) | Without it the HPAs report `<unknown>` CPU and never scale. |
| **A default StorageClass** | the Redis `StatefulSet` PVC | Or set `storageClassName` explicitly in `redis.yaml`. |
| **Prometheus Operator** (optional) | `prometheus-rules.yaml`, `servicemonitor.yaml` | Only if you want the SLO/alert rules. **Not applied by default** — see [Observability](#observability) and the note in `kustomization.yaml`. |

> **Single-node test clusters (kind / minikube / k3s)** work: the pod anti-affinity is
> `preferred` (won't block scheduling) and the PDBs allow rolling updates at `replicas: 2`.
> On `kind`, skip the registry push and load the image directly (see below).

### Build and push the image

The manifests reference `image: device-mcp-gateway:latest` as a placeholder. **There is no
published image** — build one and push it to a registry your cluster can pull from, then set
that reference in **both** `deployment.yaml` and `worker-deployment.yaml` (they share one image).

```bash
# Build (the repo root holds the Dockerfile)
docker build -t <your-registry>/device-mcp-gateway:0.1.2 .

# Push to a registry the cluster can reach (Docker Hub, GHCR, ECR, GCR, ACR, …)
docker push <your-registry>/device-mcp-gateway:0.1.2

# Point both deployments at it (never ship :latest in production — pin a tag or digest)
sed -i 's#image: device-mcp-gateway:latest#image: <your-registry>/device-mcp-gateway:0.1.2#' \
  deploy/kubernetes/deployment.yaml deploy/kubernetes/worker-deployment.yaml
```

> **kind / minikube shortcut.** To skip a registry entirely, build locally and load the image
> into the cluster: `kind load docker-image device-mcp-gateway:0.1.2` (or
> `minikube image load …`). The manifests' `imagePullPolicy: IfNotPresent` then uses the
> loaded image. Keep the `device-mcp-gateway:0.1.2` tag in both manifests in that case.

### Deploy

```bash
# Create namespace and secrets (never store secrets in the ConfigMap)
# Distributed mode requires an API key (F-23) and an authenticated Redis (F-24);
# the gateway/worker refuse to start otherwise.
kubectl create namespace mcp-gateway
REDIS_PW=$(openssl rand -hex 24)
kubectl create secret generic gateway-secrets \
  --namespace=mcp-gateway \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --from-literal=secret-key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
  --from-literal=redis-password="$REDIS_PW" \
  --from-literal=redis-url="redis://:$REDIS_PW@redis:6379/0"   # rediss:// when Redis terminates TLS

# TLS for the Ingress: the Ingress references secretName: mcp-gateway-tls.
# Either let cert-manager issue it (add an Issuer + the cert-manager.io/cluster-issuer
# annotation to ingress.yaml), or create a cert manually — e.g. a self-signed cert
# for a test deployment:
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls.key -out tls.crt -subj "/CN=mcp-gateway.example.com"
kubectl create secret tls mcp-gateway-tls \
  --namespace=mcp-gateway --cert=tls.crt --key=tls.key

# Customise before deploying:
#   Build + push the image and set it in deployment.yaml + worker-deployment.yaml
#     (see "Build and push the image" above)
#   deploy/kubernetes/ingress.yaml   — set your hostname (replaces mcp-gateway.example.com)
#   deploy/kubernetes/worker-deployment.yaml — adjust replicas / resources

# Deploy everything (Prometheus Operator CRDs are NOT required — they are excluded
# from the default kustomization; see Observability to enable them)
kubectl apply -k deploy/kubernetes/
```

Key resources deployed:
- **Redis** StatefulSet + PVC (shared state) — **single replica; out of scope for these
  manifests as an HA component.** It is a single point of failure (see `redis.yaml`); for a
  resilience/failover test, point `MCP_REDIS_URL` at managed Redis or a Sentinel/Cluster
  endpoint instead.
- **Gateway** Deployment (stateless, 2 replicas, HPA to 10) — readiness on `/readyz`, liveness on `/livez`
- **Worker** Deployment (stateful, scale independently) — liveness via a local heartbeat file
- **PodDisruptionBudgets** for gateway and worker (`minAvailable: 1`)
- **Pod anti-affinity** (preferred) spreading gateway and worker replicas across nodes
- **Hardened pod security** — non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp
- **NetworkPolicy** limiting ingress to the gateway/metrics ports and egress to DNS, Redis, and device-API ports (80/443/8080/8443 — a device on a non-standard port needs an added rule)
- **Ingress** for TLS termination

See [`docs/kubernetes-architecture.md`](docs/kubernetes-architecture.md) for the full architecture diagram and message-flow walkthrough.

---

## Observability

### Prometheus metrics

The gateway and each worker export Prometheus metrics on a **dedicated metrics port**
(`metrics.port`, default `9100`) at `GET /metrics` — RED-style HTTP and tool-call
metrics (route-template-labelled to stay low-cardinality), fleet gauges
(`mcp_registered_devices`, `mcp_active_pods`, `mcp_active_sse_connections`), and the
worker autoscaling signal `mcp_worker_pending_calls`. The gateway Deployments carry
`prometheus.io/scrape` annotations; a `ServiceMonitor` example, full metric reference,
scrape config, and Grafana starter queries are in
[docs/observability.md](docs/observability.md#prometheus-metrics).

```bash
# Scrape locally (one process):
curl -s localhost:9100/metrics | grep '^mcp_'
```

### Log format

The gateway writes to two sinks simultaneously:

| Sink | Format | Use |
|------|--------|-----|
| **stderr** | Human-readable colored text | `kubectl logs`, local dev |
| **File** (`logs/gateway.log`) | Newline-delimited JSON (default) | External collectors |

JSON is the default because Splunk, Grafana Loki, and Elasticsearch all ingest it without
custom extraction rules. Each record is a single JSON line; structured fields from
`logger.bind()` appear under `record.extra` and are directly indexable.

Toggle plain-text file output for local development:

```yaml
# config.yaml
logging:
  json_logs: false   # default is true
```

### Audit events

Every tool dispatch emits a structured `audit` event with these fields:

| Field | Description |
|-------|-------------|
| `record.extra.event` | Always `"audit"` — use this to filter audit records |
| `record.extra.hostname` | Registered device name |
| `record.extra.subject` | Authenticated principal — `key:<name>`, or `anonymous` when auth is disabled |
| `record.extra.method` | MCP JSON-RPC method (`"tools/call"`, `"tools/list"`, …) |
| `record.extra.status` | `"ok"`, `"error"`, or `"dispatched"` (distributed mode) |
| `record.extra.duration_ms` | Round-trip time in ms (embedded mode only) |
| `record.extra.rid` | Correlation ID — matches the `X-Request-Id` response header |

### Connecting an external collector

Full configuration snippets for **Grafana Loki (Promtail)**, **Splunk (UF and HEC)**,
and **Elasticsearch (Fluent Bit)** — including sample queries for each platform — are in
[docs/observability.md](docs/observability.md).

Quick reference:

```bash
# Grafana Loki — filter all audit events (LogQL)
{job="mcp-gateway"} | json | event="audit"

# Splunk (SPL)
index=mcp_gateway sourcetype=_json record.extra.event="audit"

# Trace a request by correlation ID across all log lines
{job="mcp-gateway"} | json | rid="<X-Request-Id value>"
```

The `X-Request-Id` header is returned on every API response; use it to correlate a
failed client call with the corresponding gateway and worker log entries.

---

## Troubleshooting

### Device registered but `pod_active: false`

The pod failed to start. Check `spawn_error` in `GET /v1/devices/{hostname}`:
```bash
curl http://localhost:8000/v1/devices/my-sensor
```

Common causes:
- **Unreachable device:** `base_url` is wrong, or the device is not accessible from the gateway network.
- **Spec not found:** No OpenAPI spec at any of the `discovery.spec_paths`. Provide `spec_url` explicitly.
- **Distributed mode, no worker:** Ensure `device-mcp-worker` is running and connected to the same Redis.

### Tool calls return errors

1. Check `reachable: false` — the device may have gone offline since registration. The health loop retries every `registry.health_check_interval` seconds.
2. Check the gateway logs for `circuit breaker open` — the device returned 5xx errors 5 times in a row. Wait 60 seconds for the breaker to reset, or restart the pod.
3. In distributed mode, check the worker logs for the actual httpx error.

### SSE stream connects but tool result never arrives

Ensure you are POSTing to `?session_id=<uuid>` where the UUID was taken from the `endpoint` event's `data` field — not a client-chosen value. The gateway assigns session IDs; client-supplied values are silently ignored.

### Gateway returns `503` on `/readyz`

- **Distributed mode:** The gateway cannot reach Redis. Check `MCP_REDIS_URL` and network connectivity.
- **Embedded mode:** The SQLite database is not accessible. Check `storage.db_path` and filesystem permissions.

### Credential encryption

If `gateway.secret_key` was not set when a device was registered, its `auth_config` is stored as plaintext. After setting `MCP_SECRET_KEY`, **previously registered devices must be re-registered** so their credentials are encrypted with the new key. Devices that fail to decrypt their credentials (due to key rotation) will log an error and load without credentials, causing tool calls to return 401 from the downstream API.

### Rate limiting (429 responses)

The per-IP rate limits are per gateway instance. In a multi-replica setup, a client that hits different replicas may see higher effective limits. For shared limits across replicas, configure a Redis-backed rate limiter (replace the in-memory `Limiter` in `main.py` with a `slowapi.Limiter` using a Redis storage backend).

---

## Design, security & reliability docs

Phase-0 / governance artifacts for reviewers and operators:

| Doc | What it covers |
|-----|----------------|
| [docs/tooling.md](docs/tooling.md) | OpenAPI→MCP translation contract — tool naming, parameter/body mapping, schema resolution, argument validation, error mapping |
| [docs/rbac-roles.md](docs/rbac-roles.md) | RBAC scopes, role bundles, and IdP/OIDC group→role mapping (see [ADR-0007](docs/adr/0007-federated-identity-oidc-and-gateway-rbac.md)) |
| [docs/threat-model.md](docs/threat-model.md) | STRIDE threat model — trust boundaries, adversaries, control-per-threat, accepted risks |
| [docs/threat-model-identity.md](docs/threat-model-identity.md) | Threat-model addendum for federated identity (IdP → BFF → gateway) — new boundaries, `TM-I-nn` requirements, pre-implementation gate (see [ADR-0007](docs/adr/0007-federated-identity-oidc-and-gateway-rbac.md)) |
| [docs/failure-modes.md](docs/failure-modes.md) | FMEA matrix — per-component failure, detection (metric/alert), mitigation, operator action |
| [docs/adr/](docs/adr/) | Architecture Decision Records — the load-bearing decisions (dual-mode, Redis control plane, single-owner, single-tenant, at-least-once+idempotency, fail-closed defaults, federated identity/RBAC) |
| [docs/load-testing.md](docs/load-testing.md) | Load-baseline methodology + the runnable harness in [tools/loadtest/](tools/loadtest/) |
| [docs/multitenancy.md](docs/multitenancy.md) | Single-tenant-per-stack deployment model (D-1) |
| [docs/runbook.md](docs/runbook.md) | On-call runbook — per-alert playbooks, symptom troubleshooting, standard procedures |
| [docs/upgrade.md](docs/upgrade.md) | Upgrade guide — versioning/compat policy, rolling procedure, breaking gates, rollback |
| [docs/compliance.md](docs/compliance.md) | Compliance mapping — SOC 2 TSC / HIPAA / FedRAMP-FIPS + shared-responsibility lines |

## Running Tests

```bash
make test          # full suite
make test-fast     # stop on first failure
make lint          # flake8
make typecheck     # mypy
make check         # lint + typecheck + test
```

All tests use a local mock target API — no real devices or Redis required.

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) — you may use, modify, and share this
software for **any noncommercial purpose** (evaluation, research, personal and
nonprofit/government use). Commercial use is not granted by this license.

**Commercial licensing:** a separate commercial license is available. Contact
benwold@gmail.com to discuss commercial use.

**Contributions:** by submitting a contribution you agree it is licensed under the same
terms and that the maintainer may also license it commercially (so the project can offer
commercial licenses that include your contribution).
