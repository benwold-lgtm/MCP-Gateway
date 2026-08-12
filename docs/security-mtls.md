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
  client certificate — a client cert is still presented if configured. Prefer the
  per-device form below: at the fleet level this turns verification off for *every*
  device, including the ones whose certificates are perfectly good.

## Per-device trust

The block above applies to the whole fleet. A `devices` sub-block overrides any of
the same five keys **for one device**, inheriting the rest:

```yaml
security:
  mtls:
    ca_bundle: /etc/mcp/tls/device-ca.pem       # the fleet default
    devices:
      unifi.example.internal:
        verify: false                            # this device only
      switch-a.example.internal:
        ca_bundle:   /etc/mcp/tls/vendor-a-ca.pem
        client_cert: /etc/mcp/tls/vendor-a-client.crt
        client_key:  /etc/mcp/tls/vendor-a-client.key
```

Keys are device hostnames as registered. A device with no block resolves to the fleet
profile, so adding this section changes nothing for devices it does not name.

**Why it exists.** Trust used to be fleet-global: one `ca_bundle` per process. Setting
it for a single self-signed device made that CA a trust anchor for *every* outbound
call the gateway and workers made — so any certificate that CA had signed would be
accepted for any device. `verify: false` was worse, disabling verification fleet-wide
to accommodate one appliance. Per-device profiles scope both to the device that needs
them.

### Precedence

Most specific wins:

| | Source | Beats |
|---|---|---|
| 1 | `security.mtls.devices.<hostname>.<key>` | everything below |
| 2 | `MCP_MTLS_VERIFY` (and `MCP_TLS_CLIENT_KEY_PASSWORD`) | the fleet config |
| 3 | `security.mtls.<key>` | — |

A per-device block deliberately beats the environment variable: `MCP_MTLS_VERIFY` is a
fleet-level switch, and a device that says `verify: true` is the more specific
statement. The **password** env var is the exception — it unlocks the *fleet* client
key, so it is not applied to a device that brings its own `client_cert`/`client_key`.
Such a device must name its own `client_key_password` (or use an unencrypted key);
inheriting someone else's password would either fail confusingly or silently appear to
work while both keys happened to be unencrypted.

### Failure behaviour

Both processes **refuse to start** on a bad per-device profile — every declared profile
is built at startup rather than on first contact with the device:

- an unreadable or invalid `ca_bundle` / `client_cert` names the device in the error;
- an **unknown key** inside a device block (a misspelt `ca-bundle`, say) is a hard
  error, not a warning. An ignored key there would leave that device silently on the
  fleet trust set — a security downgrade that otherwise looks exactly like success.

`GET /devices/{hostname}/diagnostics` reports the resolved profile in its `tls` field
(`source: fleet|device`, `verify`, the CA **basename**, whether a client cert is
presented), so "which trust does this device actually get?" is answerable without
reading the config on the pod.

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

`security/mtls.py::build_verify(security.mtls, hostname)` resolves the block into a
single value for httpx's `verify=` parameter:

- `True` when nothing is configured (default certifi verification),
- an `ssl.SSLContext` carrying the client cert chain and/or private CA otherwise.

An `SSLContext` (rather than the deprecated `cert=` / string `verify=` httpx
kwargs) is used so the call sites stay compatible with httpx ≥ 0.28.

Components hold a `TlsProfiles` — bound to the config block — rather than a
pre-built value, so the trust decision is made per device at the point of use.
Built contexts are cached by their **resolved** inputs, so devices that land on the
same profile (normally all of them) share one context and one file read: the cache
is bounded by the number of distinct profiles, not by the device count.

The paths that fetch specs and probe reachability keep **one `httpx.AsyncClient` per
profile** rather than one per service. A single shared client would put every device
back on one trust set, which is the limitation this design removes.

> **Trust decisions stay in OpenSSL via the stdlib.** `ssl.create_default_context`
> builds the chain and checks name constraints. Per-device trust is deliberately *not*
> built on `cryptography`'s `x509.verification` API (`PolicyBuilder`, `Store`, the
> verifiers): doing so would make `PYSEC-2026-3553` (path-building DoS) and
> `PYSEC-2026-3554` (a wildcard SAN escaping `permittedSubtrees`) reachable on exactly
> this path — and a name-constraint escape is precisely the failure this feature exists
> to prevent. See [testing-gaps.md](testing-gaps.md#tg-4--the-kubernetes-manifests-on-a-real-cluster--closed)
> and [dependency-advisories.md](dependency-advisories.md).

## Scope & limitations

- **Heterogeneous device PKIs are supported per device** (see *Per-device trust*
  above) — different CAs and different client identities can coexist in one
  deployment. What remains fleet-wide is the *set* of profiles: they come from the
  config file, so adding one is a config change and a rollout, not an API call. That
  is deliberate — `client_key` is secret material that belongs in a mounted Secret,
  not in a `devices:write` request body.
- **The OAuth2 token endpoint** (`auth/oauth2.py`) talks to an authorization
  server, not a device, and is intentionally out of scope here — it uses default
  TLS to its own (typically public) endpoint.
- mTLS secures the **gateway → device** hop. It is complementary to, not a
  replacement for, the device-side authentication configured per device (API key /
  OAuth2), which still rides inside the now-mutually-authenticated channel.
