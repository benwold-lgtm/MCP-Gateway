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

## Requirements

- Python ≥ 3.10 (3.12 recommended; used in the Docker image)

## Quick Start

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 2. Install
pip install -e ".[dev]"

# 3. Start the gateway
device-mcp
# Override host, port, or config file without editing config.yaml:
# device-mcp --host 0.0.0.0 --port 8000 --config /path/to/config.yaml

# 4. Register a device
curl -X POST http://localhost:8000/devices \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "my-sensor",
    "base_url": "http://192.168.1.42",
    "transport": "sse"
  }'

# 5. Connect an MCP client (see MCP Client Integration below)
```

## Docker

```bash
# Build and start
docker compose up -d

# Stop
docker compose down
```

The compose file mounts a named volume at `/app/data`. Set `storage.db_path` in `config.yaml` to that path so device registrations survive container restarts:

```yaml
storage:
  db_path: /app/data/devices.db
```

The default `./devices.db` path falls outside the volume and is lost on every restart.

Pass secrets as environment variables rather than storing them in `config.yaml`:

```bash
MCP_GATEWAY_API_KEY=<random-token> MCP_SECRET_KEY=<fernet-key> docker compose up -d
```

Generate a Fernet key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

To point the container at a different config file, either edit the bind-mount in `docker-compose.yml` or set the `MCP_CONFIG` environment variable.

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

The SSE transport uses a two-step protocol:

1. Open the event stream. Pass your own `client_id` or omit it to have one generated:
   ```
   GET /devices/my-sensor/sse?client_id=my-client
   ```

2. Send tool invocations on that session:
   ```bash
   curl -X POST "http://localhost:8000/devices/my-sensor/messages?client_id=my-client" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <your-api-key>" \
     -d '{"tool": "get_readings", "arguments": {"sensor_id": 1}}'
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

### No auth

Omit the `auth_type` and `auth` fields, or pass `"auth_type": "none"`.

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

## Transports

Set `transport` in the device registration payload, or configure `transport.default` in `config.yaml`.

| Transport | Status | Description |
|-----------|--------|-------------|
| `sse` | **Supported** | Server-Sent Events (default). Works with all MCP clients. |
| `http` | Not yet supported | Returns `400` at registration. Planned for a future release. |
| `stdio` | Not supported | Returns `400` at registration. stdio is not applicable in a networked gateway. |

## Configuration

All settings live in `config.yaml`. Override the file location with the `MCP_CONFIG` environment variable.

| Key | Default | Description |
|-----|---------|-------------|
| `gateway.api_key` | `""` | Bearer token required on all API routes. Empty = no auth. Override with `MCP_GATEWAY_API_KEY` |
| `gateway.secret_key` | `""` | Fernet key for encrypting device credentials in SQLite. Override with `MCP_SECRET_KEY` |
| `server.host` | `0.0.0.0` | Bind address |
| `server.port` | `8000` | Port |
| `registry.health_check_interval` | `30` | Seconds between reachability checks |
| `registry.spec_poll_interval` | `300` | Seconds between spec refresh checks |
| `registry.spec_cache_ttl` | `3600` | Spec cache lifetime in seconds |
| `registry.max_concurrent_pods` | `50` | Max simultaneous device pods |
| `auth.type` | `api_key` | Default auth type (`api_key`, `oauth2`, or `none`) |
| `discovery.timeout` | `10` | Spec discovery request timeout in seconds |
| `storage.db_path` | `./devices.db` | SQLite database path (use `/app/data/devices.db` in Docker) |
| `transport.default` | `sse` | Default MCP transport |
| `transport.sse.keep_alive_interval` | `15` | Seconds between SSE keepalive pings |
| `logging.level` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `logging.file` | `logs/gateway.log` | Log file path |

`discovery.spec_paths` is a list of URL paths probed when auto-discovering a spec. See `config.yaml` for the full default list.

## Running Tests

```bash
.venv/bin/pytest tests/ -v
```

All tests use a local mock target API — no real devices required.
