# Lite deployment (home / low-power)

Run the **whole stack** — gateway + management UI — on a Raspberry Pi, mini-PC, or an
old workstation, with one command and no cloud dependencies. This is the same codebase as
the production gateway, just run in its simplest posture:

- **Embedded mode** — in-process device pods + SQLite. **No Redis, no separate worker.**
- **Local users only** — a single password login on the UI. No SSO/OIDC to configure.
- **Self-provisioning secrets** — the UI password, session secret, and gateway API key are
  generated on first boot and printed to the logs. Nothing to hand-configure to start.
- **amd64 or arm64** — a 64-bit Raspberry Pi (4/5), Apple Silicon, or any x86 box.

```
  Browser ──▶ web (:8080) ──▶ BFF ──▶ gateway (:8000, embedded) ──▶ your devices (LAN)
                                             ▲
  LLM / MCP client ──────── SSE + Bearer ────┘
```

## Requirements

- Docker + Docker Compose v2 (`docker compose version`).
- ~1 GB free RAM. The stack is capped at roughly 0.75 + 0.5 + 0.25 CPU and ~512 MB total
  in [`docker-compose.lite.yml`](../docker-compose.lite.yml); tune the `deploy.resources`
  limits there for your box.
- A 64-bit OS. 32-bit (armv7) is not supported — several dependencies ship no 32-bit wheels.

## Quickstart (published images — no source needed)

The lite compose pulls prebuilt multi-arch images from GHCR (`:lite` tag), so you only need
the compose file itself. Docker pulls the image matching your CPU automatically:

```bash
curl -O https://raw.githubusercontent.com/benwold-lgtm/MCP-Gateway/main/docker-compose.lite.yml
docker compose -f docker-compose.lite.yml up -d
```

Then open **http://localhost:8080** and grab the generated admin login from the logs (below).

The images:

- `ghcr.io/benwold-lgtm/device-mcp-gateway:lite`
- `ghcr.io/benwold-lgtm/device-mcp-ui-bff:lite`
- `ghcr.io/benwold-lgtm/device-mcp-ui-web:lite`

### Or: build from source instead

Prefer to build locally? Clone both repos **side by side** (the UI build contexts point at
`../device-mcp-gateway-ui`), uncomment the `build:` lines in
[`docker-compose.lite.yml`](../docker-compose.lite.yml) (and comment the `image:` lines), then:

```bash
git clone https://github.com/benwold-lgtm/MCP-Gateway.git device-mcp-gateway
git clone https://github.com/benwold-lgtm/MCP-Gateway-UI.git device-mcp-gateway-ui
cd device-mcp-gateway
docker compose -f docker-compose.lite.yml up --build
```

## First-run credentials

On the first boot each component prints a banner **once**. Read them from the logs:

```bash
# UI login (username: admin) — the generated password
docker compose -f docker-compose.lite.yml logs device-mcp-ui-bff | grep -A6 first-run

# Gateway API key — the bearer token MCP/LLM clients must send
docker compose -f docker-compose.lite.yml logs gateway | grep -A8 'API key'
```

Both are persisted (UI secrets in the `bff-state` volume, the gateway key in the shared
`lite-secrets` volume), so they survive restarts and are printed only on the run that
created them.

## Connect an MCP / LLM client

Every client must present the gateway API key (from the banner above) as a bearer token —
there is no unauthenticated endpoint, even on lite.

**Clients that can send headers** (Cursor, custom agents): point them straight at the SSE
endpoint:

```
URL:            http://<this-host>:8000/v1/devices/<device-name>/sse
Authorization:  Bearer <gateway-api-key>
```

**Claude Desktop** cannot attach that header natively — a raw-URL entry will 401. Bridge
through `mcp-remote` (needs Node 18+ on the machine running Claude Desktop):

```json
{
  "mcpServers": {
    "thermostat": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote@latest",
        "http://<this-host>:8000/v1/devices/thermostat/sse",
        "--allow-http",
        "--header", "Authorization:${GATEWAY_TOKEN}"
      ],
      "env": { "GATEWAY_TOKEN": "Bearer <gateway-api-key>" }
    }
  }
}
```

`--allow-http` is needed because the lite stack speaks plain HTTP on the LAN; drop it if
you put the gateway behind TLS. Keep no space after `Authorization:` — mcp-remote splits
its args on spaces.

Registered more than one or two devices? Point the client at
`/v1/fleet/sse?devices=<name1>,<name2>,...` instead — one session covering all of them,
rather than a separate config entry (and bridge process, for clients that need one) per
device. See the main [README](../README.md#mcp-client-integration) for the full client
examples and the fleet endpoint's tool-namespacing details.

## Registering a home device

Home-automation devices (Home Assistant, smart plugs, `*.local` hosts) live on the LAN, so
the lite stack sets `MCP_ALLOW_PRIVATE_TARGETS=true` — the gateway's SSRF guard would
otherwise refuse private/loopback addresses. This is safe on a trusted home network; leave
it off on anything internet-facing. Register a device against the gateway API (bearer token
required):

```bash
curl -X POST http://localhost:8000/v1/devices \
  -H "Authorization: Bearer <gateway-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "thermostat", "base_url": "http://192.168.1.50"}'
```

…or use the **Register** form in the UI.

Device publishes no OpenAPI spec (UniFi consoles, printers, many IoT hubs)? Write a
minimal one by hand and register with `spec_url` — walkthrough and a working UniFi example
in [examples/specs/](../examples/specs/).

## Self-signed device certificates

Home devices that speak HTTPS (UniFi consoles, Home Assistant, NAS boxes) almost always
serve a **self-signed certificate**, which the gateway's outbound TLS verification rejects
— registration succeeds but spec fetch and tool calls fail. Two ways out:

- **Preferred: trust the device's CA.** If the device (or your LAN) has a CA you can
  export, point the gateway at it and verification keeps working:

  ```yaml
  # config.yaml
  security:
    mtls:
      ca_bundle: /path/to/lan-ca.pem
  ```

- **Pragmatic: disable outbound verification** with one env var on the gateway container
  (no config-file mount needed):

  ```yaml
  # docker-compose override, or add to the gateway service's environment
  environment:
    MCP_MTLS_VERIFY: "false"
  ```

  The env var overrides `security.mtls.verify` in either direction; unset, the config
  value (default `true`) wins.

Scope and risk of `verify: false`: it applies to **all** of the gateway's outbound device
connections (spec fetch, health probes, tool calls) — not just one device — and means the
gateway can't detect a machine-in-the-middle between it and your devices. That's usually
acceptable on a trusted, closed home LAN; it is not acceptable anywhere untrusted traffic
can route. It does not affect the browser↔UI or client↔gateway connections.

## Before you expose it beyond localhost

The out-of-the-box defaults assume a trusted LAN over plain HTTP. Before putting this on a
wider network:

- **Pin your own secrets.** Create a `.env` next to the compose file:
  ```bash
  MCP_API_KEY=$(openssl rand -hex 24)     # gateway key (shared with the BFF)
  SESSION_SECRET=$(openssl rand -hex 32)  # signs the UI session cookie
  UI_ADMIN_PASSWORD=<your-password>
  ```
  Any value you set takes precedence over the generated one.
- **Terminate TLS** with a reverse proxy in front of `:8080`, and set `COOKIE_SECURE=true`
  on the BFF so the session cookie is only sent over HTTPS.
- **Keep `MCP_ALLOW_PRIVATE_TARGETS` off** unless the box only ever talks to a trusted LAN.

For anything beyond a home setup, use the production paths instead: distributed mode
(Redis + workers) and the [Kubernetes deployment](../README.md#kubernetes-deployment).

## Resetting / rotating secrets

- **New UI password / session secret:** delete `bootstrap.json` from the `bff-state`
  volume, or just set `UI_ADMIN_PASSWORD` / `SESSION_SECRET` in `.env`.
- **Rotate the gateway key:** delete `gateway-api-key` from the `lite-secrets` volume (a new
  one is generated on next boot), or set `MCP_API_KEY`.

```bash
docker compose -f docker-compose.lite.yml down
docker volume rm mcp-gateway-lite_bff-state mcp-gateway-lite_lite-secrets   # regenerate both
docker compose -f docker-compose.lite.yml up -d
```

## Maintainer note: publishing the images

The `:lite` images are built and pushed by the release workflows
([gateway](../.github/workflows/release-image.yml),
[UI](../../device-mcp-gateway-ui/.github/workflows/release-images.yml)) on a version tag.
On the **first** publish, GHCR creates each package **private** — set its visibility to
**Public** in the repository's package settings so home users can pull without
authenticating.
