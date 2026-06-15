# Changelog

All notable changes to the Device MCP Gateway are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, **minor releases may include breaking changes** — read
the notes for each release before upgrading. See [docs/upgrade.md](docs/upgrade.md).

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

[0.1.1]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.1
[0.1.0]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.0
