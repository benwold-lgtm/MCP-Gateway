# Mutual TLS to devices (F-31)

The gateway and workers make **outbound HTTPS calls to device APIs** on several
paths:

| Path | Component | Mode |
|------|-----------|------|
| Tool calls | `DevicePod` | embedded + distributed |
| Reachability probe / spec discovery | `Registry` | embedded |
| Reachability probe / spec poll | `WorkerHealthLoop` | distributed |
| Spec fetch on pod spawn | `DeviceWorker` | distributed |

By default these do anonymous-client TLS and verify the device's server
certificate against the public CA set (certifi — the same trust store httpx uses).
F-31 lets you:

- **present a client certificate** (mutual TLS) to a device that requires one, and/or
- **verify the device's server certificate against a private CA**, and/or
- (closed test networks only) **disable verification**.

Every outbound-to-device path listed above honours the same configuration, so an
mTLS-protected device is reachable for tool calls **and** health/spec probes — a
partial application would leave the device looking unreachable.

## Configuration

```yaml
security:
  mtls:
    client_cert: /etc/mcp/tls/client.crt      # PEM client cert (may also contain the key)
    client_key:  /etc/mcp/tls/client.key      # PEM private key (omit if combined into client_cert)
    client_key_password: ""                    # prefer the env var below
    ca_bundle:   /etc/mcp/tls/device-ca.pem    # verify device server certs against THIS CA
    verify: true                               # NEVER false in production
```

Omit the whole `mtls:` block for default behaviour (anonymous client, public-CA
server verification). Behaviour is byte-for-byte unchanged when it is absent.

### Field semantics

- **`client_cert` / `client_key`** — the certificate (and private key) the gateway
  presents during the TLS handshake. If the key is bundled into the cert PEM, set
  only `client_cert`. Without these, calls are anonymous-client TLS.
- **`client_key_password`** — passphrase for an encrypted private key. Prefer the
  environment variable **`MCP_TLS_CLIENT_KEY_PASSWORD`**, which overrides the config
  value, so the secret need not live in the config file (mounted via a K8s Secret
  / env, same pattern as the metrics token in F-36).
- **`ca_bundle`** — when set, device **server** certificates are verified against
  *this* CA only (it replaces the public set — the common private-PKI case). When
  unset, the public certifi set is used.
- **`verify: false`** — disables server verification entirely (no hostname check,
  `CERT_NONE`). Only for a trusted closed test network. It does **not** disable the
  client certificate — a client cert is still presented if configured.

## Kubernetes

Mount the cert/key/CA from a `Secret` and point the config (or env) at the mount:

```yaml
volumeMounts:
  - name: device-mtls
    mountPath: /etc/mcp/tls
    readOnly: true
env:
  - name: MCP_TLS_CLIENT_KEY_PASSWORD
    valueFrom:
      secretKeyRef: { name: device-mtls-key-password, key: password }
volumes:
  - name: device-mtls
    secret:
      secretName: device-mtls   # client.crt, client.key, device-ca.pem
```

The cert files must be present on **both** the gateway (embedded mode) and the
workers (distributed mode), since both make outbound device calls.

## Implementation

`security/mtls.py::build_verify(security.mtls)` resolves the block into a single
value for httpx's `verify=` parameter:

- `True` when nothing is configured (default certifi verification),
- an `ssl.SSLContext` carrying the client cert chain and/or private CA otherwise.

An `SSLContext` (rather than the deprecated `cert=` / string `verify=` httpx
kwargs) is used so the call sites stay compatible with httpx ≥ 0.28. Built
contexts are cached by their resolved inputs, so all device clients that share
the one global config share a single context.

## Scope & limitations

- **One global config applies to every device.** This fits the common case — a
  single gateway PKI identity and a single device CA. **Heterogeneous device PKIs**
  (different client certs / CAs per device) are a planned extension: `build_verify`
  is already keyed by resolved inputs and would accept a per-device override layered
  over the global default. Until then, devices that need *different* client
  identities must run on separate gateway/worker deployments (consistent with the
  single-tenant-per-deployment model, D-1).
- **The OAuth2 token endpoint** (`auth/oauth2.py`) talks to an authorization
  server, not a device, and is intentionally out of scope here — it uses default
  TLS to its own (typically public) endpoint.
- mTLS secures the **gateway → device** hop. It is complementary to, not a
  replacement for, the device-side authentication configured per device (API key /
  OAuth2), which still rides inside the now-mutually-authenticated channel.
