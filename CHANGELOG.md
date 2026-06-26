# Changelog

All notable changes to the Device MCP Gateway are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, **minor releases may include breaking changes** — read
the notes for each release before upgrading. See [docs/upgrade.md](docs/upgrade.md).

## [Unreleased]

Post-0.1.2 changes: third-party Kubernetes deployment hardening (no application code),
plus a small tool-set change-governance addition (a new read endpoint) and a translation
doc — both from a third-party review. Plus the first slice of federated identity
(ADR-0007): inbound OIDC at the gateway, with static keys kept as break-glass.

### Added

- **Inbound OIDC authentication (ADR-0007, first slice).** The gateway can now authenticate
  a request bearing an IdP-issued JWT, in addition to static API keys. A new composite
  authenticator validates the token against the issuer's JWKS — asymmetric-algorithm
  allow-list (`HS*`/`none` refused), `iss`/`aud`/`exp`/`nbf` with bounded clock skew, `kid`
  matched to a published key — then maps the token's group claim to gateway scopes via a
  `gateway.oidc.group_roles` table the gateway owns. Static keys are tried for opaque tokens
  and remain the **break-glass** path: OIDC fails *closed* (a JWT is rejected) when the
  IdP/JWKS is unreachable, while configured keys keep working. JWKS is cached with a bounded
  TTL and kid-miss refetches are rate-limited (no fetch-amplification DoS); the issuer/JWKS
  URLs go through the existing egress (SSRF) policy. Disabled by default; enable under
  `gateway.oidc`. Implements TM-I-08/09/10/12 from
  [docs/threat-model-identity.md](docs/threat-model-identity.md). The BFF OIDC login flow and
  per-user identity relay (I1/I2/I4) are the next slices.
- **Three seed RBAC roles** — `operator` (manage devices + DLQ, no tool calls), `auditor`
  (metrics only), and `caller` (machine agent: read + `tools:call`) — join `admin`/`viewer`
  in `ROLE_SCOPES`, matching [docs/rbac-roles.md](docs/rbac-roles.md). Additive; no route
  changes (routes authorize on scopes, never role strings).
- **`GET /v1/devices/{hostname}/tools/diff`** — surfaces a device's most recent tool-set
  change (added / removed / changed tool names, the `breaking` flag and reasons, and the
  `tools_revision` it produced) as `ToolsDiffResponse`. The diff was already computed and
  audited on every spec change (F-41) but discarded; it is now persisted per device (cleared
  on delete) and served, so a UI can show *what* moved, not just *that* it moved. Works in
  both modes and does not require an active pod.
- **`docs/tooling.md`** — the OpenAPI→MCP translation contract: tool naming, parameter and
  request-body mapping, `$ref`/`allOf`/`anyOf`/nullable schema resolution, argument
  validation, and the two-layer error mapping (JSON-RPC codes + result-envelope slugs).

### Changed

- **Kubernetes manifests hardened.** Gateway and worker pods now run with
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, all Linux capabilities
  dropped, and a `RuntimeDefault` seccomp profile (writable `emptyDir` mounts added for
  `/app/logs`, and `/tmp` on the worker for its liveness file). Preferred pod anti-affinity
  spreads gateway and worker replicas across nodes so the `minAvailable: 1` PDBs are
  meaningful and node-failure/failover can be exercised.
- **Gateway `replicas` is now `2`**, matching the HPA's `minReplicas` (was `1`, which
  contradicted the autoscaler).
- **`prometheus-rules.yaml` is no longer applied by default.** It (and the new
  `servicemonitor.yaml`) require the Prometheus Operator CRDs, so a `kubectl apply -k` on a
  cluster without the Operator would fail. Both are now opt-in; the pods still expose
  `/metrics` and carry `prometheus.io/scrape` annotations for annotation-based discovery.

### Added

- **`deploy/kubernetes/servicemonitor.yaml`** — optional Prometheus Operator scrape config
  for the gateway and worker metrics ports, so metric discovery and the alert rules assume
  the same Prometheus setup.
- **Documentation for third-party deployment**: a "Build and push the image" workflow (the
  manifests reference an unpublished image), a cluster-prerequisites table (ingress-nginx,
  metrics-server, default StorageClass, optional Prometheus Operator), a TLS-secret example,
  and an explicit note that the bundled single-replica Redis is not an HA component.

## [0.1.2] - 2026-06-16

A second hardening patch. A follow-up third-party review confirmed every v0.1.1 fix was
genuine and test-backed, and flagged five lower-severity tails — two narrow SSRF residuals
and three reliability/correctness bugs. All five are fixed here.

### Security

- **OAuth2 token fetch is now SSRF-guarded.** `token_endpoint` was validated at register/PUT
  but the token request — which carries the `client_secret` in its body — went through an
  unguarded client, so a DNS-rebind between registration and fetch could exfiltrate the
  secret to an internal/metadata address. The fetch now re-validates the endpoint (and every
  redirect hop) against the egress policy.
- **Device tool-call dispatch re-validates the target on every call.** Dispatch already
  refused to follow redirects; it now also runs the SSRF guard per call, so a rebind of an
  already-registered device to an internal address is caught at dispatch time, not only at
  registration. (The validate→connect window remains the documented residual that full
  IP-pinning would close.)

### Fixed

- **A failed tool-call dispatch is no longer silently dropped.** In distributed mode, a call
  whose execution raised was acked without a dead-letter or a client response, so the caller
  hung until timeout. It is now dead-lettered (for inspect/replay) and the client receives a
  definitive error.
- **The shared rate-limiter can no longer leave an "immortal" counter.** A crash between the
  counter increment and its expiry could leave a key with no TTL, throttling that client
  forever. The increment and expiry now run as one atomic step, and a missing expiry
  self-heals on the next request. (Requires Redis 7, the documented deployment target.)
- **`$ref`s nested in array items or map values are now resolved.** A `$ref` inside an
  array's `items` or an object's `additionalProperties` was left dangling in the generated
  tool schema; both are now resolved like object properties.

## [0.1.1] - 2026-06-15

A security and correctness patch. A third-party re-review of v0.1.0 found six issues that
the inaugural release's verification missed — the smoke test exercised only the embedded,
no-request-body path, which was structurally blind to every one of them. All six are fixed
here. v0.1.0 remains published; this is the first release with no known correctness
regressions in either mode.

### Security

- **SSRF egress policy now covers redirects and every fetch path** (F-02 hardening). Spec
  discovery / fetch followed HTTP redirects without re-validating the target, and workers
  never consulted the policy at all — so a redirect or DNS-rebind to a private / loopback /
  cloud-metadata address bypassed the front-door check. Outbound spec fetches now go through
  an SSRF-guarded transport that validates **every hop**, and device tool-call dispatch no
  longer follows cross-origin redirects (also closing an API-key/credential-leak vector).
  `security.mtls.verify: false` now emits a startup warning. (Residual, documented: full
  DNS-rebind / TOCTOU IP-pinning is not closed — the deterministic vectors are.)
- **OAuth2 `token_endpoint` is validated against the egress policy.** A device registered
  with an attacker-chosen `token_endpoint` could exfiltrate its client secret to an internal
  or metadata address; it is now policy-checked like `base_url` / `spec_url`.

### Fixed

- **Distributed: manifest caching crashed for any device with a request body.**
  `RequestBodySpec.binary_fields` (a set) wasn't JSON-encodable, so caching the manifest
  raised and the device was unusable in distributed mode. The Redis round-trip also silently
  dropped request-body and parameter-rename metadata. Both now round-trip losslessly.
- **Distributed: a metadata-only `PUT /devices/{host}` wiped stored credentials.**
  Reconstructing auth from the encrypted-at-rest record failed and re-registered the device
  with no auth. A PUT that omits auth now preserves the stored credentials verbatim.
- **Distributed: device unassignment / config-replace could be ignored.** Unassign events
  were load-balanced to one arbitrary worker rather than the device's owner, so a pod could
  keep running after teardown and a `PUT` replace might never apply its new config. Unassign
  is now broadcast so the owning worker always tears down.
- **Embedded: `GET /devices/{host}/tools` always returned 409.** The embedded path never
  cached the manifest, so REST tool introspection failed even though MCP `tools/list` worked
  off the live pod. The manifest is now cached on pod spawn.
- **Audit chain reported false tampering under a multi-replica gateway.** Multiple replicas
  appending to one shared audit sink interleaved independent hash chains, which the verifier
  read as a break. Records are now tagged per replica and each replica's sub-chain is verified
  independently; existing single-replica logs verify unchanged.

### Added

- `MCP_INSTANCE_ID` — overrides the per-replica audit-chain identity (defaults to `HOSTNAME`,
  i.e. the pod name under Kubernetes). Only relevant when multiple gateway replicas write to a
  shared audit sink.

### Note

The v0.1.0 notes stated every review finding (F-01–F-65) was resolved; the re-review showed
that verification was incomplete. The changes above close that gap.

## [0.1.0] - 2026-06-15

First tagged release. A universal bridge that converts any OpenAPI-documented device or
service into an [MCP](https://modelcontextprotocol.io/) tool server: register a device by
URL, the gateway auto-discovers its OpenAPI spec, translates every operation into an MCP
tool, and serves it over SSE for LLM clients.

This release is the output of a comprehensive security, reliability, and operability review
(findings F-01–F-65); every finding is resolved except one deferred item (see
[Known limitations](#known-limitations)). The embedded-mode golden path
(register → auto-discover → translate → invoke over SSE) is verified end-to-end.

### Added

- **Two deployment modes from one codebase**
  ([ADR-0001](docs/adr/0001-dual-mode-embedded-distributed.md)).
  - **Embedded** (default): single process, SQLite, zero infrastructure — install and run.
  - **Distributed**: stateless gateway tier + Redis control plane + independently-scaled
    stateful workers; single-owner-per-device with lease-based failover and reassignment.
- **Security, fail-closed by default.**
  - API-key authentication with **RBAC scopes** (`admin` / `viewer`). Distributed mode
    refuses to start without auth, or against an unauthenticated Redis — explicit override
    flags exist for trusted local networks only.
  - **SSRF / egress policy**: private, loopback, and link-local targets are refused by
    default (cloud-metadata safe); opt in with `MCP_ALLOW_PRIVATE_TARGETS` for a trusted fleet.
  - **LLM-surface hardening**: header-injection defenses, schema-poisoning sanitization,
    response-size caps, server-side argument validation, and `resources/read` traversal guards.
  - **Credential protection**: Fernet encryption at rest with **zero-downtime MultiFernet
    key rotation** (`device-mcp-rotate-secrets`); credentials redacted from logs.
  - **End-to-end identity propagation** (gateway → worker → audit), optional **outbound mTLS**
    to devices, and an **adversarial test suite** (SSRF / injection / fail-open / poisoning).
- **Reliability.**
  - Bounded, jittered retries on idempotent outbound calls; an **at-most-once idempotency
    guard** for non-idempotent calls on reclaim.
  - **Admission control** with a visible `429` (no silent stream-trim), per-device and
    per-worker in-flight caps, and circuit breakers.
  - Scale-out **rebalancing**, a leader-elected reconciler with lease-flap hysteresis,
    graceful drain, and **dead-letter-queue inspect / replay / drain**.
  - Upstream `429` / `Retry-After` awareness.
- **Integration correctness.** Robust OpenAPI→tool translation (param-collision and
  path-interpolation fixes), normalized error shapes (an upstream ≥400 is no longer returned
  as a successful result), non-JSON / form / multipart request bodies, a per-device adapter
  seam, and **breaking-change governance** with a monotonic `tools_revision` signal.
- **Observability & operability.** Prometheus metrics, **SLO recording + burn-rate alerts**,
  operational alerts for silent failure modes, optional OpenTelemetry tracing, `/v1` API
  versioning, config validation (warns on typos), safe-default startup warnings, a device
  diagnostics endpoint, and an error catalog with `rid` correlation.
- **Compliance & audit.** A tamper-evident, hash-chained **audit stream** (privileged actions
  plus 401/403 with actor), per-request actor attribution, time-based retention, and a
  **SOC 2 / HIPAA / FedRAMP control map** ([docs/compliance.md](docs/compliance.md)).
- **Documentation.** Threat model, failure-mode matrix, six ADRs, an on-call
  [runbook](docs/runbook.md), an [upgrade guide](docs/upgrade.md), multitenancy and compliance
  docs, and a load-test harness.

### Known limitations

- **Resilience is designed but not yet empirically demonstrated** (F-63): the
  chaos / fault-injection plan (experiments E1–E10) is written but requires a live platform
  to execute. Analysis only so far.
- **Not FIPS-validated**: credential encryption uses Fernet (AES-128-CBC + HMAC), which is
  not a FIPS 140-validated module — a blocker for FedRAMP / FISMA-High as shipped. Mitigation:
  delegate credential secrecy to a FIPS-validated KMS (see [docs/compliance.md](docs/compliance.md)).
- **Single-tenant per stack** ([D-1](docs/adr/0004-single-tenant-per-stack.md)): tenant
  isolation is a deployment-boundary control, not in-application. Run one stack per tenant.
- **Pull-only**: OpenAPI `webhooks` / `callbacks` are not translated, and there is no
  long-running-operation (202 / job-poll) support — calls are synchronous.

[0.1.2]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.2
[0.1.1]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.1
[0.1.0]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.0
