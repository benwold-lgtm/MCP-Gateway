# Changelog

All notable changes to the Device MCP Gateway are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, **minor releases may include breaking changes** — read
the notes for each release before upgrading. See [docs/upgrade.md](docs/upgrade.md).

## [Unreleased]

## [0.2.0] - 2026-08-06

A feature release: the gateway can now federate a **remote MCP server** as a device, not only
an OpenAPI service. It also carries the resolution of an independent third-party review (12
findings, all closed) and the defects found by first running the stack on a real Kubernetes
cluster.

**Read before upgrading.** Two security fixes **change request handling**, two add **startup
gates a misconfigured deployment will now hit**, and one **tightens tool-argument validation**
in a way that is breaking for callers passing arguments that do not exist.

### Security

- **Dependency refresh**, clearing 7 of the 10 advisories `pip-audit` reported against the
  previous pins — notably `starlette` 1.2.1 → 1.3.1, `cryptography` 48.0.0 → 48.0.1, `mcp`
  1.27.2 → 1.29.0 and `uvicorn` 0.48.0 → 0.52.1. No constraint changes were needed.
  **None of the 10 were reachable from this codebase** — the refresh was taken because it was
  free, not because anything was exploitable. The reachability analysis, and the method for
  redoing it next time, are in the new
  [dependency-advisories.md](docs/dependency-advisories.md). The three that remain need
  `cryptography>=49`, which the deliberate major cap blocks; they target PKCS#7 decryption and
  the `x509.verification` API, neither of which this project calls.
- **`X-Forwarded-For` was attacker-controlled, so any client could choose its own rate-limit
  bucket.** The rate limiter keyed on the *left-most* XFF entry when `trust_proxy_headers`
  was on. nginx, traefik and the k8s ingresses **append** to that header rather than replace
  it, so a caller who sent their own `X-Forwarded-For` owned the left-most value — and could
  reset their counter simply by rotating it, defeating per-IP limits entirely and poisoning
  IP-based audit attribution. The client is now resolved by walking the header
  **right-to-left** from the TCP peer, popping hops while each falls inside the new
  `security.trusted_proxy_cidrs`; the first hop outside them is the client. A caller who
  skips the proxy is stopped at the first step, because their own peer address isn't trusted,
  and their header is never read. **Breaking:** enabling `gateway.trust_proxy_headers`
  without `security.trusted_proxy_cidrs` is now refused at startup — trusting the header
  without knowing which hops are yours is what created the hole.
- **DNS-rebinding race in the SSRF guard.** `validate_target_url` resolved the host, then
  httpx resolved it *again* when connecting — two lookups, so a 0-TTL alternating record
  could pass validation and connect to the blocked address. Validating more often does not
  close that window; the checked address has to *be* the dialled one. The validated address
  is now pinned through to connect, with `Host`/`sni_hostname` carrying the original name so
  virtual hosting and TLS certificate verification are unaffected.
- **Outbound port policy.** `http://host:22/` was accepted, so the guard could be aimed at a
  non-HTTP service to port-scan or smuggle a payload into another protocol. Ports carrying a
  non-HTTP protocol (22, 25, 3306, 6379, 27017, …) are now refused by default, plus
  2375/2376 — which *are* HTTP but expose the Docker daemon as a direct RCE pivot. Ordinary
  HTTP ports including non-standard ones (8000, 8080, 8443) are unaffected;
  `security.allowed_target_ports` switches to a strict allowlist for a tighter posture.
- **Weak static API keys are refused in production.** `MCP_ADMIN_KEY=admin` was accepted
  silently. A static key is a full bearer credential — and with OIDC enabled it is also the
  break-glass path that still works when the IdP is down. Keys under 16 characters or
  matching a common-value list now warn in every mode and **refuse to start in distributed
  mode** (`gateway.allow_weak_keys` overrides). The floor sits below anything this project
  generates or documents, so a real deployment is unaffected.
- **OAuth2 refresh tokens rotated at runtime were never persisted**, so a provider that
  rotates on use eventually locked the device out.

### Added

- **MCP passthrough — federate a remote MCP server as a device.** Registering with
  `upstream_kind: "mcp"` points the gateway at a server that already speaks MCP; its tools are
  discovered from `tools/list` and proxied rather than translated from an OpenAPI document.
  A remote server is a **device**, not a second entity type — it reuses `DeviceConfig`,
  `base_url` (already SSRF-validated), and the `hostname` namespace, so RBAC, rate limiting,
  admission control, the circuit breaker, dead-lettering, audit, fleet sessions and tool-change
  governance all apply with no new code. Rationale, the alternatives rejected, and the itemised
  cost register for a future tenancy retrofit are in
  [ADR-0009](docs/adr/0009-mcp-passthrough.md).

  Three things are worth knowing before pointing it at someone else's server:

  - **The upstream authors its own tool contract and can change it after review** — the
    rug-pull and tool-poisoning threats, now [threat-model.md](docs/threat-model.md) §B5.
    Detection is the change-governance machinery: every poll diffs and classifies the tool set,
    and a removed tool or a newly-required parameter is **breaking** and alertable. Structural
    sanitisation (F-26) strips control characters and bidi overrides from upstream names and
    descriptions; prose survives by design, because a proxy cannot adjudicate meaning.
  - **Protections that live in the translator had to be re-applied**, since a proxied tool
    never passes through it: text sanitisation (F-26) and the tool-count/payload caps (F-09).
    Argument validation (F-28), header-injection resistance (F-25) and the guarded client's
    SSRF policy apply unchanged.
  - **v1 proxies tools only** — no resources, no prompts, no stdio upstreams; and
    `upstream_transport: "sse"` is accepted by the schema but refused at registration.

  Implements MCP revision `2025-06-18` in both directions. Current is `2026-07-28`, which is
  **not** backwards compatible — it removes the `initialize` handshake, `Mcp-Session-Id` and
  SSE resumability in favour of a stateless per-request protocol. Interop across the two eras
  exists only where an implementation deliberately supports both. Tracked as its own piece of
  work; the passthrough seam is where it lands.
- **`mcp_oidc_validation_failures_total{reason}`.** OIDC validation failures fell through to
  static keys at `debug` log level, so an IdP or JWKS outage silently degraded the whole
  deployment to break-glass-keys-only with no operator signal, and forged-JWT probing
  produced nothing at all. Failures are now counted and warned about (rate-limited to one per
  minute, carrying the suppressed count). `reason` is a fixed six-value set rather than the
  error text, because the raw error embeds attacker-controlled JWT contents and would be an
  unbounded-cardinality vector.
- **[docs/testing-gaps.md](docs/testing-gaps.md)** — what is implemented and reasoned about
  but **not empirically validated**, and why: chaos/fault injection (F-63), the scale
  baseline, HA Redis failover, live-cluster verification, and arm64 runtime verification.

### Changed

- **Redis client now survives a failover.** `create_redis` passed only `socket_timeout` and
  `max_connections` — no retry, health check or connect timeout — so a primary failover
  reached callers as a burst of hard `ConnectionError`s and pointing the gateway at an HA
  Redis bought almost nothing. Now configured with jittered exponential-backoff retries,
  `retry_on_error`, `health_check_interval` and `socket_connect_timeout`. The jitter is
  deliberate: a failover hits every replica and worker at once, so an un-jittered curve has
  them retry in lockstep against the newly promoted primary. The budget (~2.5s by default) is
  sized to absorb the reconnect burst and a *short* election, **not** to block through a long
  Sentinel promotion — stalling a request for tens of seconds is worse than failing it.
  See [testing-gaps.md](docs/testing-gaps.md) (TG-3) for what remains unverified.
- **Kubernetes manifests are digest-pinned to a published image.** They referenced
  `device-mcp-gateway:latest`, which has no registry component and so resolved to Docker Hub —
  following the k8s docs produced `ImagePullBackOff`. Both deployments now pin by digest to
  the multi-arch GHCR image, with `imagePullPolicy` explicit and identical on both (the
  worker previously set none, defaulting to `Always` under `:latest` while the gateway used
  `IfNotPresent`, so the two could run different builds of the same tag). `kustomization.yaml`
  gains an `images:` block so retargeting is one edit rather than two.
- **CI coverage floor ratcheted 65% → 81%** (measured actual is 83%), and the CI-gating dev
  tools (`black`, `flake8`, `mypy`, `pytest`) are upper-bounded — `black --check` is a
  blocking gate, so an unbounded spec let an upstream major turn an unrelated PR red.

### Fixed

- **A device's cached manifest expired an hour after its pod spawned and never came back**, so
  a healthy device silently became undiscoverable. The manifest is stored with
  `ex=spec_cache_ttl`, but its only writers were the spawn path (which runs only when the cache
  is *already* empty) and the changed-spec branch of the health loop — and the spec poll
  returned early whenever the hash matched, which is the normal case for a stable device.
  Nothing renewed the key. The pod kept its manifest in memory throughout, so MCP clients saw
  no problem at all while `GET /devices/{h}/tools` returned 409, **`GET /v1/fleet/sse` returned
  404 "no reachable devices" for an entire healthy fleet**, and the UI showed a reachable,
  pod-active device with zero tools. The manifest is now renewed on every poll of an unchanged
  spec — a lease held up by the worker serving the device, lapsing once none does — and rebuilt
  from the current spec if it has already gone, instead of waiting for a pod respawn. Found on
  a live cluster four hours into a run; no test had ever let a TTL elapse.
- **A device's tools accepted arguments it could not send.** Generated tool schemas carried no
  `additionalProperties`, so a call naming an argument that does not exist validated cleanly,
  was dropped on the way to the device — there is nowhere to put it — and came back as a
  success. To a model, a successful call is confirmation that the argument it invented is
  real, so the failure mode is a hallucination the gateway corroborates rather than a lost
  value. Generated schemas are now closed, which states a fact: the translator lists every
  argument the dispatcher can place. **Breaking for any caller that was sending extra
  arguments** — they were already being discarded, and are now refused with the offending
  field named. Schemas published by a **proxied MCP upstream are untouched**: that contract
  belongs to the upstream, and tightening it could refuse calls its server would accept.
- **Gateway and workers exited on the first Redis connection failure at startup** instead of
  waiting for it. Start order is not guaranteed on any orchestrator, so the common cause is
  simply that Redis has not finished starting. Kubelet backoff does recover — which is why
  this was easy to miss — but it recovers by way of a stack trace and a restart count, the
  same signals an operator uses to spot a genuinely broken deployment (observed on a live
  cluster as two restarts per worker). Both now wait for Redis with jittered backoff up to
  the new `redis.startup_timeout` (default 60 s), then fail hard so a truly dead Redis still
  reaches probes and alerts. Set `redis.startup_timeout: 0` for the old fail-fast behaviour.
  This is a separate budget from `redis.retries`, which stays short on purpose: a request
  caught mid-failover should fail fast rather than block its caller.
- **An idle MCP session expired under a stream the client still had open.** The session TTL was
  refreshed inside the results-stream reader but *after* the branch handling an elapsed
  `XREAD` block, so it was unreachable on a session carrying no results — i.e. a connected
  client waiting, which is the steady state. After 24 h the session key vanished and the next
  POST got a 404 for a session that was, from the client's side, plainly alive. Found while
  auditing every TTL'd key after the manifest defect above; the rest (leader locks, device
  claims, heartbeats) renew correctly, and the short-lived ones are meant to expire.
- **Tool-change governance never ran in distributed mode.** The worker's health loop compared
  each spec poll against `spec_hash`, but the only writers of that field lived in the
  registry-side spec services, which distributed mode does not run — so the field stayed empty,
  the `if cfg.spec_hash and ...` guard was permanently false, and the branch that would have
  written the first baseline sat *inside* the branch that could never be entered. The effect
  was not a stale hash: breaking-change detection, `tools_revision`, `GET /devices/{h}/tools/diff`
  and the breaking-change alert (F-41) could not fire at all, for either upstream kind. A device
  could drop a tool, or an MCP upstream rewrite a tool description into a prompt-injection
  payload, and the gateway would keep serving the old manifest and say nothing. The spawn path
  now records the fingerprint of the spec it built the manifest from, and a poll that finds no
  baseline seeds one instead of discarding it. Found on a live cluster; every pre-existing test
  had constructed its device with `spec_hash` already set.
- **Embedded `tools/call` was recorded as an error on every success**, inverting both
  `mcp_tool_calls_total` and the audit outcome for the entire embedded-mode dispatch path.
- **`mcp` was unbounded (`>=1.0.0`)**, so a clean install resolved to 2.0.0, which removed
  `mcp.server.fastmcp` — CI had been red on every branch. Now bounded, with a test asserting
  critical dependencies reject the next major.
- **Documentation pointed at an image tag that does not exist** (`:0.1.2`, 404 on GHCR), and
  `docs/upgrade.md` referenced a `device-mcp-worker` image that has never existed — the worker
  runs the gateway image with a different command.

## [0.1.4] - 2026-07-06

### Fixed

- **Lite deployment: `MCP_API_KEY_FILE` silently never wrote a key.** The Dockerfile never
  created a `/secrets` path, so when the lite compose mounted a brand-new named volume
  there, Docker seeded it as an empty **root-owned** directory (Docker copies whatever the
  image has at a fresh volume's mount point, ownership included — a path that doesn't exist
  in the image at all gets a bare root-owned directory instead). The non-root `appuser` the
  gateway runs as couldn't write to it, so first-run bootstrap failed permission-denied and
  quietly fell back to "no key configured" — auth stayed **disabled** on a supposedly
  secured-by-default lite deployment. Fixed by pre-creating and chowning `/secrets` in the
  image, matching the existing pattern already used for `/app/data` and `/app/logs`.
- **`/health` and the FastAPI app reported a stale version.** `__version__` was a second,
  independently-maintained literal in `device_mcp_gateway/__init__.py` that drifted out of
  sync with `pyproject.toml`'s version at the 0.1.3 release. Now derived at import time from
  installed package metadata (`importlib.metadata.version`), so there is a single source of
  truth and this class of drift can't recur.

## [0.1.3] - 2026-07-05

Post-0.1.2 changes: third-party Kubernetes deployment hardening (no application code),
plus a small tool-set change-governance addition (a new read endpoint) and a translation
doc — both from a third-party review. The first slice of federated identity (ADR-0007):
inbound OIDC at the gateway, with static keys kept as break-glass. Plus a lite / home
deployment profile for low-power boxes.

### Added

- **Lite / home deployment profile.** A one-command stack for low-power hosts (Raspberry Pi,
  mini-PC, old workstation; amd64 or arm64) via `docker-compose.lite.yml` — the gateway in
  embedded mode (no Redis/worker) plus the management UI, local password login only. First
  boot self-provisions the admin API key: with `MCP_API_KEY_FILE` set (opt-in) the gateway
  generates + persists a key to a shared volume and prints it for MCP-client config, and the
  BFF reads the same file via `GATEWAY_TOKEN_FILE`. No-op unless the env var is set, so
  existing key resolution is unchanged. Multi-arch (amd64+arm64) images publish to GHCR on
  release tags. See [docs/lite-deploy.md](docs/lite-deploy.md).
- **`GET /v1/auth/me` (whoami).** Returns the authenticated caller's own `subject`, effective
  `scopes`, and `auth_method`. Requires authentication but no specific scope. It lets a UI/BFF
  gate views on the **gateway's** scopes instead of maintaining a parallel role model, so the
  two can't drift (ADR-0007) — the source of truth for the UI's scope-driven gating.
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
- **Redis HA guidance** ([docs/kubernetes-architecture.md](docs/kubernetes-architecture.md),
  "Redis availability & durability"): the enterprise options for a highly-available Redis —
  managed Redis (drop-in single endpoint) or self-hosted Redis/Valkey + Sentinel behind a
  primary-tracking endpoint — why the gateway needs single-primary **HA, not a sharded
  Cluster** (multi-key `MULTI`/`EXEC` + pub/sub on one keyspace) and not active-active,
  durability/AOF, the Redis 7 requirement, and that the single-URL client makes any
  failover-hiding endpoint a no-code change. `redis.yaml` now points at it.

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
  to execute. Analysis only so far. This and every other unvalidated claim — the scale
  baseline, HA Redis failover, live-cluster and arm64 verification — are tracked in
  [docs/testing-gaps.md](docs/testing-gaps.md).
- **Not FIPS-validated**: credential encryption uses Fernet (AES-128-CBC + HMAC), which is
  not a FIPS 140-validated module — a blocker for FedRAMP / FISMA-High as shipped. Mitigation:
  delegate credential secrecy to a FIPS-validated KMS (see [docs/compliance.md](docs/compliance.md)).
- **Single-tenant per stack** ([D-1](docs/adr/0004-single-tenant-per-stack.md)): tenant
  isolation is a deployment-boundary control, not in-application. Run one stack per tenant.
- **Pull-only**: OpenAPI `webhooks` / `callbacks` are not translated, and there is no
  long-running-operation (202 / job-poll) support — calls are synchronous.

[0.2.0]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.2.0
[0.1.4]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.4
[0.1.3]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.3
[0.1.2]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.2
[0.1.1]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.1
[0.1.0]: https://github.com/benwold-lgtm/MCP-Gateway/releases/tag/v0.1.0
