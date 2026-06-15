# Threat Model — Device MCP Gateway

Phase-0 artifact (F-22). This is the structured security model behind the controls that
the security review (findings F-02..F-38, F-55..F-60) put in place. It states what the
system protects, who the adversaries are, where the trust boundaries lie, and — per
STRIDE element — the threats and the control that addresses each. Use it when reviewing
a change: if a change crosses or moves a trust boundary, revisit the relevant row.

Companion docs: [multitenancy.md](multitenancy.md) (tenancy decision D-1),
[security-mtls.md](security-mtls.md), [audit-logging.md](audit-logging.md),
[failure-modes.md](failure-modes.md) (availability/reliability counterpart).

## 1. Scope & assets

The gateway converts OpenAPI-documented devices into MCP tool servers. The assets worth
protecting, in priority order:

| Asset | Why it matters |
|-------|----------------|
| **Device credentials** (API keys, OAuth2 client secrets) | Stored at rest; compromise grants direct access to upstream devices |
| **The upstream devices themselves** | The gateway holds network reach + credentials to call them; it is a confused-deputy target |
| **The control plane** (Redis: registry, assignments, call streams) | Whoever writes it controls pod placement and can inject/observe tool calls |
| **Gateway API-key / RBAC material** | Grants device CRUD + tool invocation |
| **The audit trail** | Compliance + incident reconstruction; valuable to tamper with |
| **LLM-facing tool metadata + responses** | A poisoning vector into the connected model (indirect prompt injection) |

## 2. Trust boundaries

```
            (B1)            (B2)                 (B3)               (B4)
 LLM client ───► Gateway ───► Redis control ───► Worker ───► Device API
  (untrusted)   (trusted)     plane (trusted    (trusted)   (semi-trusted:
                              infra)                          attacker-influenced
                                                              data, see §4)
```

- **B1 — Client → Gateway.** The primary authn/authz boundary. Everything inbound is
  untrusted until a `Principal` is established.
- **B2 — Gateway → Redis.** Network boundary to shared infra. Redis holds credentials and
  the call streams; an unauthenticated Redis is a full-takeover path.
- **B3 — Redis → Worker.** Workers consume assignments + tool calls from Redis. Per
  Decision **D-1** (single-tenant-per-stack) the worker *trusts the stream contents*: the
  gateway is the authorization point, so this is not an isolation boundary within a stack.
- **B4 — Worker → Device.** Outbound to an upstream that is only *semi*-trusted: its spec
  text and response bodies are attacker-influenceable and flow toward the LLM.

## 3. Adversaries

1. **Unauthenticated network attacker** — can reach the gateway port and/or Redis.
2. **Authenticated low-privilege principal** (`viewer`) — has a valid key, tries to exceed
   its scope or call tools.
3. **Malicious / compromised upstream device** — serves a hostile OpenAPI spec or hostile
   responses to poison the LLM or attack the worker.
4. **Malicious tool caller via the LLM** — supplies crafted tool arguments (injection,
   traversal, SSRF, over-posting).
5. **Insider / log reader** — can read logs or stored state; tries to harvest secrets or
   tamper with the audit trail.

Out of scope: a fully compromised host/root on a gateway or worker node; a malicious
operator with the `MCP_SECRET_KEY`; cross-tenant attacks within one stack (explicitly
excluded by D-1 — tenants get separate stacks).

## 4. STRIDE by boundary

### B1 — Client → Gateway

| STRIDE | Threat | Control (finding) |
|--------|--------|-------------------|
| **S**poofing | Unauthenticated caller acts as a privileged user | Bearer-key auth; **fail-closed** in distributed mode — refuses to start with no keys unless `allow_anonymous` (F-23). Principal resolved to `subject` for every request (F-56) |
| **T**ampering | Oversized/chunked body to bypass size guard or exhaust memory | Pure-ASGI streaming body cap, rejects understated/missing/ chunked `Content-Length` before buffering (F-35) |
| **R**epudiation | "I never made that call / change" | Privileged actions + 401/403 audited with `subject` (F-55); per-request access log bound to principal (F-56); tamper-evident hash-chained audit stream (F-57) |
| **I**nformation disclosure | Session hijack — post to a known `session_id` | Sessions bound to the opening principal; foreign `subject` → 403 (F-37). Metrics endpoint optionally bearer-gated (F-36) |
| **D**enial of service | Flood the gateway or a hot device | Per-IP + per-principal rate limits (F-16); admission control sheds with 429 past the call-backlog watermark (F-06); spec ingestion size/op/time bounds (F-09) |
| **E**levation of privilege | `viewer` performs a mutation or tool call | Scope checks at the RBAC dependency seam; missing scope → 403, audited (F-32/F-55) |

### B2 — Gateway/Worker → Redis

| STRIDE | Threat | Control (finding) |
|--------|--------|-------------------|
| **S**poofing / **T**ampering | Anyone on the network reads state or injects into call/assignment streams | Distributed mode **refuses an unauthenticated Redis** (no password) unless `redis.allow_insecure` (F-24); deployment uses `rediss://` TLS (F-31 internal leg) |
| **I**nformation disclosure | Credentials readable in Redis | Credentials encrypted at rest with Fernet; gateway/worker won't persist plaintext in distributed mode (F-24/F-34) |
| **R**epudiation | — | Audit stream is per-process and forwarded to a retained sink (F-57/F-58) |

### B3 — Redis → Worker (intra-stack, per D-1 not an isolation boundary)

| STRIDE | Threat | Control (finding) |
|--------|--------|-------------------|
| **S**poofing | Worker can't attribute who issued a call | Principal `subject` rides the call stream into the worker's execution audit (F-30 residual) — attribution, not isolation |
| **T**ampering | Replayed/duplicated stream delivery double-executes a write | At-most-once idempotency guard on non-idempotent methods, keyed on `request_id` (F-08) |
| **E**levation | Cross-tenant access via shared worker process | **Accepted within a stack** (D-1/F-33): do not co-host tenants; isolate by separate stack |

### B4 — Worker → Device

| STRIDE | Threat | Control (finding) |
|--------|--------|-------------------|
| **T**ampering (confused deputy) | Tool arg injects upstream auth headers / overrides them | Reserved + auth headers applied **last**; CRLF/reserved header params stripped (F-25) |
| **I**nformation disclosure (SSRF) | Crafted `base_url`/`spec_url`/`resources/read` path reaches internal services | URL policy blocks private/loopback/link-local + bad schemes at register/update; `resources/read` rejects traversal/non-rooted paths (F-02/F-29) |
| **T**ampering (path injection) | Tool arg traverses or injects path segments | Path params URL-encoded (`quote(safe="")`) before interpolation (F-04) |
| **S**poofing (server identity) | Worker talks to an impostor device | Optional outbound mTLS / private CA per the mTLS config (F-31) |
| **Spec/response poisoning** | Hostile spec text or response body injects the LLM | Device-supplied LLM-facing text sanitized (control/zero-width/bidi stripped, length-capped) (F-26); response bodies size-capped + normalized, 4xx surfaced honestly not as success (F-27/F-39). **Residual:** semantic prompt injection is a client-side concern — documented |
| **D**enial of service | Huge/slow spec starves the translation pool | Size cap + operation-count cap + per-translation timeout (F-09) |

## 5. Cross-cutting controls

- **Least-privilege RBAC** — `admin`/`viewer` roles, scope-gated routes (F-32).
- **Defense in depth at the edge** — body cap, rate limits, admission control, arg
  validation against the tool JSON schema (F-28) before any upstream call.
- **Secret hygiene** — Fernet-encrypted credentials with zero-downtime key rotation
  (`MultiFernet`, F-34); URL userinfo redacted before logging (F-59); secrets passed as
  env vars, never the ConfigMap.
- **Tamper-evident, retained audit** — hash-chained stream, time-based retention, SIEM
  forwarding seam (F-57/F-58).

## 6. Accepted risks & residuals

| Risk | Disposition |
|------|-------------|
| No in-app multi-tenant isolation (flat namespace, global scopes, shared worker process) | **Accepted (D-1)** — single-tenant-per-stack; isolate by separate stack. See [multitenancy.md](multitenancy.md) |
| Worker trusts stream contents | **Accepted (D-1)** — gateway is the authz point within a stack |
| Semantic prompt injection via device data | **Residual** — structurally sanitized; semantic intent is a client-model concern |
| Fernet is not FIPS-validated | **Tracked (F-60)** — matters only for FedRAMP; see [compliance-mapping.md](compliance-mapping.md) when added |
| SSE is replica-pinned (soft gateway statefulness) | **Accepted (F-20)** — documented; affects availability not confidentiality |
| Single global mTLS identity for all devices | **Documented limitation (F-31)** — heterogeneous per-device PKI → separate deployment |

## 7. Maintenance

Revisit this model when: a new trust boundary is introduced (e.g. a direct gateway↔worker
channel, an inbound webhook surface — see [api-change-governance.md](api-change-governance.md)),
the tenancy decision (D-1) changes, the auth model changes (JWT/OIDC), or a new asset class
is stored. Each STRIDE row should map to a control with a finding ID or an explicit accepted
risk — a row with neither is a gap.
