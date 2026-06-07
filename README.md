# Device MCP Gateway

A universal bridge that converts any OpenAPI-documented device or service into an [MCP](https://modelcontextprotocol.io/) tool server. Register a device by URL, the gateway auto-discovers its OpenAPI spec, translates every operation into an MCP tool, and serves it over SSE — ready for LLM clients (Claude Desktop, Cursor, custom agents) to invoke.

## Architecture

The gateway supports two modes selected by `registry.mode` in `config.yaml`.

### Distributed mode (production)

```
LLM clients
    │  SSE (GET /devices/{hostname}/sse)
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
curl -X POST http://localhost:8000/devices \
  -H "Content-Type: application/json" \
  -d '{"hostname": "my-sensor", "base_url": "http://192.168.1.42", "transport": "sse"}'

# 5. Connect an MCP client (see MCP Client Integration below)
```

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
curl -X POST http://localhost:8000/devices \
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
      "url": "http://localhost:8000/devices/my-sensor/sse"
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
  http://localhost:8000/devices/my-sensor/sse
```

The first event is `endpoint` and its `data` is the POST URL for this session:
```
event: endpoint
data: /devices/my-sensor/messages?session_id=<server-assigned-uuid>
```

**Step 2 — Send a tool invocation on that session:**
```bash
curl -X POST "http://localhost:8000/devices/my-sensor/messages?session_id=<uuid-from-step-1>" \
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
| `viewer` | `devices:read`, `metrics:read` | read device state + `/metrics/summary`; **no** mutations or tool calls (403) |

Configure keys via `gateway.api_key` (legacy single key = `admin`), `MCP_ADMIN_KEY` / `MCP_VIEWER_KEY`, or a `gateway.rbac` list of `{name, key, role}` (see [config.yaml](config.yaml)). If no key is set anywhere, auth is disabled (all requests permitted). The authenticated principal is recorded as `subject` in audit logs. The seam (`authenticate()` → `Principal{subject, scopes}`) is built to swap to JWT/OIDC later without touching routes.

Rate limits (per source IP): `/health` and `/readyz` — 300 req/min; `POST /devices` — 60 req/min; `POST /messages` — 600 req/min. Returns 429 on excess.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe — process status, active pod count |
| `GET` | `/readyz` | Readiness probe — backend connectivity (Redis or SQLite) |
| `POST` | `/devices` | Register a device |
| `PUT` | `/devices/{hostname}` | Update a device config (replaces and restarts pod) |
| `DELETE` | `/devices/{hostname}` | Unregister a device |
| `GET` | `/devices` | List all registered devices |
| `GET` | `/devices/{hostname}` | Get a single device's status |
| `GET` | `/devices/{hostname}/tools` | List a device's MCP tools |
| `GET` | `/devices/{hostname}/sse` | Open SSE stream (MCP transport) |
| `POST` | `/devices/{hostname}/messages` | Send a JSON-RPC 2.0 message via SSE |
| `GET` | `/metrics/summary` | Reachability counts and per-device rate-limit state (JSON, auth-protected) |
| `GET` | `/admin/overview` | Aggregate fleet counts + device list in one call (UI/BFF enabler; `devices:read`) |

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

**`GET /devices/{hostname}`:**
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

**`POST /devices` / `PUT /devices/{hostname}`:**
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

#### OAuth2 (Client Credentials)
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

---

## Security

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

```bash
# Create namespace and secrets (never store secrets in the ConfigMap)
kubectl create namespace mcp-gateway
kubectl create secret generic gateway-secrets \
  --namespace=mcp-gateway \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --from-literal=secret-key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Customise before deploying:
#   deploy/kubernetes/ingress.yaml   — set your hostname
#   deploy/kubernetes/deployment.yaml — set your image tag (never use :latest)
#   deploy/kubernetes/worker-deployment.yaml — adjust replicas / resources

# Deploy everything
kubectl apply -k deploy/kubernetes/
```

Key resources deployed:
- **Redis** StatefulSet + PVC (shared state)
- **Gateway** Deployment (stateless, scale freely) — readiness probes on `/readyz`
- **Worker** Deployment (stateful, scale independently) — liveness probe via Redis heartbeat key
- **PodDisruptionBudgets** for gateway and worker (`minAvailable: 1`)
- **NetworkPolicy** limiting ingress to the gateway port
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

The pod failed to start. Check `spawn_error` in `GET /devices/{hostname}`:
```bash
curl http://localhost:8000/devices/my-sensor
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
