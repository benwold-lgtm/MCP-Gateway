# hermeshome — Device MCP Gateway

A universal bridge that converts any OpenAPI-documented device or service into an [MCP](https://modelcontextprotocol.io/) tool server. Register a device by URL, the gateway auto-discovers its OpenAPI spec, translates every operation into an MCP tool, and serves it over SSE, stdio, or HTTP — ready for LLM clients to invoke.

## Architecture

```
LLM client
    │  SSE / stdio / HTTP
    ▼
FastAPI control plane  (POST /devices, GET /devices/…/sse, …)
    │
    ▼
Registry  ──── health loop (30 s) ──── SpecCache (TTL 1 h)
    │
    ▼
SpecTranslator  (OpenAPI 3.x → McpManifest)
    │
    ▼
DevicePod  (one FastMCP server per device)
    │  httpx
    ▼
Target device API
```

Registered devices are persisted in a local SQLite database (`devices.db`) and reconnected automatically on restart.

## Quick Start

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 2. Install
pip install -e ".[dev]"

# 3. Start the gateway
uvicorn device_mcp_gateway.main:app --host 0.0.0.0 --port 8000

# 4. Register a device
curl -X POST http://localhost:8000/devices \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "my-sensor",
    "base_url": "http://192.168.1.42",
    "transport": "sse"
  }'

# 5. Connect an MCP client
# SSE stream:  GET http://localhost:8000/devices/my-sensor/sse
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/devices` | Register a device |
| `GET` | `/devices` | List all registered devices |
| `DELETE` | `/devices/{hostname}` | Unregister a device |
| `GET` | `/devices/{hostname}/sse` | Open SSE stream (MCP transport) |
| `POST` | `/devices/{hostname}/messages` | Send a tool invocation via SSE |
| `GET` | `/health` | Gateway health + active pod count |
| `GET` | `/metrics` | Reachability and cache stats |

### Register device payload

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
  }
}
```

`spec_url` is optional — the gateway tries common paths (`/openapi.json`, `/swagger.json`, etc.) if omitted.

## Authentication

### API Key

```json
{
  "auth_type": "api_key",
  "auth": { "api_key": "my-key", "header_name": "X-API-Key" }
}
```

### OAuth2 (Client Credentials)

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

## Configuration

Key settings in `config.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `server.host` | `0.0.0.0` | Bind address |
| `server.port` | `8000` | Port |
| `registry.health_check_interval` | `30` | Seconds between reachability checks |
| `registry.spec_poll_interval` | `300` | Seconds between spec refresh checks |
| `registry.max_concurrent_pods` | `50` | Max simultaneous device pods |
| `storage.db_path` | `./devices.db` | SQLite database path |
| `transport.default` | `sse` | Default MCP transport |
| `logging.level` | `INFO` | Log verbosity |

## Running Tests

```bash
.venv/bin/pytest tests/ -v
```

All tests use a local mock target API — no real devices required.
