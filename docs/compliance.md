# Compliance Framework Mapping — Device MCP Gateway

Where the gateway's technical controls land against common compliance frameworks, what
the **operator** still owns, and the hard limits to know before you scope an audit.

> **This is an engineering control map, not a certification.** A SOC 2 / HIPAA / FedRAMP
> outcome depends on your *whole* environment — policies, the hosting platform, the people
> controls — not just this component. Use this to brief auditors on what the software
> provides and to draw the shared-responsibility line; do not read it as a compliance
> claim.

The product is **`0.x`** and **single-tenant per stack** (ADR-0004 / D-1): there is no
in-application tenant isolation. **Tenant separation is a deployment-boundary control** —
one stack (its own Redis, `MCP_SECRET_KEY`, API keys) per tenant. Every framework mapping
below assumes that boundary; see [multitenancy.md](multitenancy.md).

---

## Shared-responsibility model

| Layer | Owner |
|-------|-------|
| Technical controls *in the software* (authn/authz, input validation, audit emission, at-rest/in-transit crypto hooks, rate limiting, fail-closed gates) | **Gateway** — this repo |
| Deployment boundary (per-tenant stack), secret management/KMS, network policy, TLS termination, host hardening | **Operator** |
| Retained, hold-capable, tamper-evident **copy of record** of the audit stream (SIEM/WORM) | **Operator** — the gateway emits and locally hash-chains; durability/retention of the system of record is yours |
| Policy, risk acceptance, personnel, vendor management, physical security | **Operator** |
| Classifying the data devices expose and whether tool I/O may be logged downstream | **Operator** — the gateway is a conduit; it does not log tool args/results |

---

## SOC 2 (Trust Services Criteria, 2017)

Mapping the Common Criteria plus the **Availability** and **Confidentiality** categories
— the ones this component materially supports. Each row: what the software provides → what
the operator must add.

### Common Criteria — security

| TSC | Gateway provides | Operator adds |
|-----|------------------|---------------|
| **CC2 / CC3** (information, risk assessment) | [threat-model.md](threat-model.md) (STRIDE), [failure-modes.md](failure-modes.md) (FMEA), [ADRs](adr/) — documented boundaries, risks, accepted residuals | Org-level risk assessment, vendor/asset inventory |
| **CC6.1** (logical access) | API-key auth; **RBAC scopes** enforced at a central dependency seam; distributed mode **refuses to start without auth** (F-23) | Key issuance/rotation policy, least-privilege scope assignment |
| **CC6.6** (boundary protection) | Egress **SSRF/target policy** (F-02/F-29) blocks private/loopback targets; header-injection defenses (F-25); arg-schema validation (F-28); schema-poisoning sanitization (F-26); response-size cap (F-27); spec-ingestion bounds (F-09) | Network policy, ingress WAF/TLS, the per-tenant deployment boundary (D-1) |
| **CC6.7** (transmission & disposal) | At-rest credential encryption (Fernet/MultiFernet); **credential redaction** in logs (F-59); Redis-auth gate (F-24); time-based audit disposal (F-58) | TLS in transit (terminate at ingress / mutual TLS — see [security-mtls.md](security-mtls.md)); KMS for key custody; documented disposal schedule |
| **CC7.1 / CC7.2** (detection & monitoring) | Prometheus metrics, **SLO recording + burn-rate alerts**, operational alerts for silent failure modes (`prometheus-rules.yaml`); OTel tracing (opt-in) | Wire alerts to paging; retain metrics; SIEM ingestion |
| **CC7.2 / CC7.3** (audit logging, anomaly evaluation) | `event="audit"` stream — privileged actions + **401/403 with actor** (F-55), per-request **actor attribution** (F-56); **tamper-evident hash chain** (F-57) with offline verifier | Forward the dedicated audit sink to a retained append-only store; review process |
| **CC7.4** (incident response) | [runbook.md](runbook.md) — per-alert playbooks; `rid` correlation across gateway→worker; DLQ inspect/replay/drain (F-10) | IR plan, on-call, post-incident review |
| **CC8** (change management) | Config validation warns on drift (F-50); safe-default warnings (F-53); **tool-surface change governance** + breaking-change signal (F-41); [upgrade.md](upgrade.md) | Change-approval workflow, CI/CD controls, the project's own release process |

### Availability (A-series)

| TSC | Gateway provides | Operator adds |
|-----|------------------|---------------|
| **A1.1** (capacity) | [Load-baseline methodology + harness](load-testing.md); admission control sheds visibly past a backlog watermark (F-06); per-worker in-flight caps (F-13) | Capacity planning against a measured baseline; HPA/limits tuning |
| **A1.2** (resilience/recovery) | Lease-based failover + reconciler reassignment (F-07); at-most-once idempotency guard (F-08); circuit breakers; bounded jittered retries (F-05/F-61); DLQ (F-10); readiness gating | HA Redis, multi-replica + PDBs, backup/restore drills |
| **A1.3** (recovery testing) | Documented SLOs/error budgets; chaos experiment plan (F-63, deferred to a live platform) | Run DR/chaos exercises; verify the backups restore |

### Confidentiality (C-series)

| TSC | Gateway provides | Operator adds |
|-----|------------------|---------------|
| **C1.1** (confidential-data protection) | Device credentials encrypted at rest (Fernet); not logged; tool args/bodies/results **never logged or persisted** (conduit model) | Data classification; downstream-logging decisions; KMS |
| **C1.2** (disposal) | Time-based audit retention/disposal (F-58); credential delete removes ciphertext | Documented disposal schedule; SIEM-side retention policy |

---

## HIPAA (Security Rule, technical safeguards)

**Only relevant if devices expose PHI.** The gateway is a **conduit** — PHI in tool
results flows *through* to the MCP client and is **not stored or logged** by the gateway
(see the data-handling table in [audit-logging.md](audit-logging.md)). Whether the
"conduit exception" applies, and whether a BAA is needed, is your counsel's call.

| §164.312 safeguard | Gateway support |
|--------------------|-----------------|
| (a)(1) Access control | API-key auth + RBAC scopes; fail-closed (F-23) |
| (a)(2)(iv) Encryption at rest | Fernet credential encryption (see FIPS caveat below) |
| (b) Audit controls | `event="audit"` stream, actor attribution, hash chain (F-55/56/57) |
| (c)(1) Integrity | Tamper-evident audit chain + offline verifier (F-57) |
| (d) Transmission security | Redis-auth gate (F-24); TLS is operator-terminated |
| — Retention (§164.316(b)(2), 6 years) | `logging.audit_retention` set to your window (e.g. `"7 years"`) + forward to a retained sink |

PHI **at rest** inside the gateway is limited to device *credentials* (not patient data);
set retention and disposal to your policy and forward audit to a hold-capable store.

---

## FedRAMP / FIPS — the hard limit

**Credential encryption uses Fernet, which is *not* FIPS 140-validated.** Fernet is
AES-128-CBC + HMAC-SHA256 in a non-validated cryptographic module. For any program that
**requires FIPS-validated cryptography** (FedRAMP, FISMA High, DoD), this is a blocker as
shipped:

- **Do not represent the at-rest credential encryption as FIPS-compliant.** It is sound
  cryptography, but not a validated module.
- **Mitigation path:** keep device credentials out of the gateway's at-rest store and
  delegate secrecy to a **FIPS-validated KMS / secrets manager** (the operator's KMS holds
  the material; the gateway references it), and terminate TLS with a FIPS-validated module
  at the boundary. The application-layer Fernet store is then not the system of record for
  the secret.
- This is tracked as the FedRAMP/FIPS residual in the evaluation (F-60); a FIPS-validated
  codec backend is a future option, not a current capability.

Everything else in the SOC 2 map (access control, audit, monitoring, availability) applies
to a FedRAMP scoping too — the crypto-module validation is the specific gap to close first.

---

## Maintenance

Update a row when a control changes (a new finding resolved, a gate added/removed, an audit
field added). Keep the **shared-responsibility line** explicit on every addition: state
what the software does *and* what the operator must still own — an unqualified "we are
compliant" claim is exactly what this document exists to prevent.
