# Hand-written specs — when a device publishes no OpenAPI spec

The gateway normally discovers a device's OpenAPI spec by probing well-known paths
(`discovery.spec_paths`: `/openapi.json`, `/swagger.json`, ...). Plenty of real devices —
UniFi consoles, printers, cameras, older IoT hubs — expose a perfectly usable HTTP API but
publish **no spec at all**. That doesn't rule them out: write a minimal spec yourself, host
it anywhere the gateway can reach, and register the device with `spec_url` pointing at it.

This directory holds working examples, starting with
[`unifi-network-integration.json`](unifi-network-integration.json) — the spec we use to put
a UniFi console's sites/devices/clients behind the gateway.

## Writing one

1. **Find the endpoints.** Vendor API docs if they exist; otherwise the browser dev-tools
   network tab against the device's own web UI, or `curl` guesses. You only need the
   handful of operations you actually want as tools — this is not documentation, it's an
   interface contract.
2. **Write a minimal OpenAPI 3.0.3 file, as JSON.** The gateway parses fetched specs as
   JSON (a YAML file will be rejected). Per operation you need: the path + method,
   parameters, and an `operationId`. Two rules of thumb:
   - **`operationId` becomes the MCP tool name** (see [docs/tooling.md](../../docs/tooling.md)
     for the full naming contract), so pick stable, snake_case, verb-first ids —
     `list_clients`, not `getClientsV1Handler`.
   - **Keep response schemas loose** (plain `type: object` with the fields you care
     about, no `required`, no `additionalProperties: false`) so a firmware update that
     adds a field doesn't break anything.
3. **Validate it** with the same library the gateway uses:

   ```bash
   pip install openapi-spec-validator
   python3 -c "import json; from openapi_spec_validator import validate; \
   validate(json.load(open('examples/specs/unifi-network-integration.json'))); print('ok')"
   ```

4. **Host it** anywhere the gateway can GET it — a raw GitHub URL, a path on an existing
   internal web server, or in a pinch a one-liner on any LAN box:

   ```bash
   python3 -m http.server 8081   # serves ./unifi-network-integration.json
   ```

   If the spec URL resolves to a private/LAN address, the gateway's SSRF guard must allow
   it (`MCP_ALLOW_PRIVATE_TARGETS=true` — the lite stack already sets this).

5. **Register with `spec_url`:**

   ```bash
   curl -X POST http://localhost:8000/v1/devices \
     -H "Authorization: Bearer <gateway-api-key>" \
     -H "Content-Type: application/json" \
     -d '{
       "hostname": "unifi",
       "base_url": "https://<console-ip>",
       "spec_url": "http://<spec-host>:8081/unifi-network-integration.json",
       "auth_type": "api_key",
       "auth": {"api_key": "<unifi-api-key>", "header_name": "X-API-KEY"}
     }'
   ```

The auth config lives in the registration (encrypted at rest when `MCP_SECRET_KEY` is
set), **not** in the spec — the spec's `securitySchemes` block is documentation only.

## The UniFi example, specifically

- Create the API key in the UniFi console: **Settings → Control Plane → Integrations →
  Create API Key**. It is sent as an `X-API-KEY` header (the registration above).
- The Integration API lives under `/proxy/network/integration/v1/...` on the console
  itself (UniFi Network 9.0+); `base_url` is just `https://<console-ip>`.
- Self-hosted consoles serve a **self-signed certificate**, so spec fetch and tool calls
  will fail TLS verification out of the box. On a trusted home LAN, disable outbound
  verification with `MCP_MTLS_VERIFY=false` — scope and risk in
  [docs/lite-deploy.md](../../docs/lite-deploy.md#self-signed-device-certificates).
- The example covers the read-only operations (sites, devices, clients). The Integration
  API also has write endpoints (port-forward rules, client blocking, ...) — add them to
  your copy the same way if you want the LLM to have them, and think twice before you do.

Verify what the gateway will derive from your spec before registering, straight from a
repo checkout:

```bash
python3 -c "
import json
from device_mcp_gateway.core.translator import SpecTranslator
m = SpecTranslator().translate(json.load(open('examples/specs/unifi-network-integration.json')), hostname='unifi')
print([t.name for t in m.tools])
"
```
