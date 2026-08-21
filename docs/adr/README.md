# Architecture Decision Records

Phase-0 artifact (F-22). ADRs capture the *load-bearing* architectural decisions — the
ones that are expensive to reverse and that a reviewer or new contributor would otherwise
have to reverse-engineer from the code. Each record is immutable once **Accepted**: to
change a decision, add a new ADR that **supersedes** the old one (don't edit history).

Format: [0000-template.md](0000-template.md) (a trimmed MADR). Decisions that predate this
register were reconstructed from the codebase, the evaluation findings register, and the
`D-1`/`D-2` decisions logged there.

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-dual-mode-embedded-distributed.md) | Dual-mode: embedded (in-process/SQLite) and distributed (Redis + workers) | Accepted |
| [0002](0002-redis-control-plane.md) | Redis Streams + pub/sub as the distributed control plane | Accepted |
| [0003](0003-single-owner-per-device.md) | Single-owner per device — do not shard a device across pods (D-2) | Accepted |
| [0004](0004-single-tenant-per-stack.md) | Single-tenant-per-stack — tenancy by deployment boundary, not in-app isolation (D-1) | Accepted — extended by [0013](0013-two-plane-tenancy-and-the-provider-plane.md) |
| [0005](0005-at-least-once-with-idempotency-guard.md) | At-least-once stream delivery + an at-most-once idempotency guard for writes | Accepted |
| [0006](0006-fail-closed-distributed-defaults.md) | Fail-closed security gates in distributed mode (auth + Redis) | Accepted |
| [0007](0007-federated-identity-oidc-and-gateway-rbac.md) | Federated identity (OIDC) + break-glass local keys; gateway owns RBAC | Accepted — its `TM-I-nn` threat-model gate walked against the code 2026-08-21; hardened by [0023](0023-gateway-break-glass-attribution.md) |
| [0008](0008-fleet-sessions.md) | Fleet MCP sessions — aggregate multiple devices into one client-facing session | Accepted |
| [0009](0009-mcp-passthrough.md) | MCP passthrough — a remote MCP server is a device, not a second entity | Accepted |
| [0010](0010-tool-derived-request-headers.md) | Tool-derived request headers — adopt SEP-2243 for OpenAPI, exclude passthrough permanently | Accepted |
| [0011](0011-backup-and-restore.md) | Backup/restore — ciphertext archives by default, portable export behind its own scope | Accepted |
| [0012](0012-federation-credential-model.md) | Credential model for BFF provider federation — preserve per-user relay, BFF audit first | Proposed — **the only record still open**, and three of its four Decision items were overtaken by [0017](0017-provider-authority-is-delegated.md) without any record noticing. Item 1 stands; items 3/4 have no remaining occasion; item 2's scope needs re-deriving once [0021](0021-separate-console-applications.md) lands. See its *Scope after the 2026-08-21 review* |
| [0013](0013-two-plane-tenancy-and-the-provider-plane.md) | Two-plane tenancy — isolated tenant stacks, and a provider plane above them | Accepted — §4/§5a/§6/§6a/§8/§11 superseded by [0017](0017-provider-authority-is-delegated.md), §5b by [0018](0018-device-credentials-by-reference.md) §6; **provider-plane code removed** (PR #139). §1/§2/§3/§7/§9/§10 stand |
| [0014](0014-tenant-namespace-naming-and-network-isolation.md) | Tenant namespace naming (pseudonymous, deterministic) + default-deny network isolation between tenants | Accepted |
| [0015](0015-endpoint-fingerprinting.md) | Endpoint fingerprinting — pin TLS SPKI + declared identity, warn on change, opt-in fail-closed | Accepted |
| [0016](0016-reaching-many-tenant-gateways.md) | Reaching many tenant gateways — routing, not fan-out | **Rejected** — superseded before acceptance by [0017](0017-provider-authority-is-delegated.md)–[0021](0021-separate-console-applications.md); kept for its rejected alternatives |
| [0017](0017-provider-authority-is-delegated.md) | Provider authority over a tenant is **delegated by that tenant**, never asserted by the provider — supersedes [0013](0013-two-plane-tenancy-and-the-provider-plane.md) §4/§5a/§6/§8/§11 | Accepted |
| [0018](0018-device-credentials-by-reference.md) | Device credentials held **by reference**, never at rest in the gateway — supersedes most of [0011](0011-backup-and-restore.md) | Accepted |
| [0019](0019-opaque-tenant-identity.md) | The tenant identifier is **opaque from birth** — supersedes [0014](0014-tenant-namespace-naming-and-network-isolation.md) §1 | Accepted |
| [0020](0020-the-device-catalog.md) | The provider's write path is a **catalog**; tenants claim from it — device types *and* provider-operated services. Answers D2 | Accepted |
| [0021](0021-separate-console-applications.md) | Provider and tenant consoles are **separate applications** — supersedes [0013](0013-two-plane-tenancy-and-the-provider-plane.md) §3 as a runtime property | Accepted |
| [0022](0022-agent-initiated-device-writes-are-plan-bound.md) | Agent-initiated device writes are **plan-bound**, not standing access — `caller` keeps its baseline and elevation is per reviewed plan | Accepted — implementation still blocked on ADR-0018 §6's plan digest slice, which is specified but not yet built |
| [0023](0023-gateway-break-glass-attribution.md) | Gateway break-glass is individually attributable, rate-limited, and loud — hardens [0007](0007-federated-identity-oidc-and-gateway-rbac.md)'s static-key mechanism to meet [0017](0017-provider-authority-is-delegated.md) §4's four required properties | Accepted |
| [0024](0024-tenant-provisioning-is-a-request.md) | Tenant provisioning is a **request** the console files and GitOps fulfils — the console never provisions a stack. Defines the mechanism [0014](0014-tenant-namespace-naming-and-network-isolation.md)/[0017](0017-provider-authority-is-delegated.md)/[0019](0019-opaque-tenant-identity.md)/[0021](0021-separate-console-applications.md)/[0023](0023-gateway-break-glass-attribution.md) all already depend on | Accepted |

When you add an ADR: copy the template, take the next number, set status `Proposed`, and
add a row here. Flip to `Accepted` when merged.

**0017–0021 are one decision in five records.** They reorient the tenancy model on a single
principle — *the provider holds less and reaches less* — and each supersedes a different part
of what came before. Read [0017](0017-provider-authority-is-delegated.md) first; the other four
follow from it.

## Implementation order

Re-ranked 2026-08-20, once every open question in the set was closed. The original ordering —
0019 → 0018 → 0020 → 0017 → 0021 — assumed all five records were unbuilt. Two are now wholly or
partly shipped, and 0022/0023 have since joined, so the live order is:

| # | Work | Why it sits here |
|---|------|------------------|
| — | [0019](0019-opaque-tenant-identity.md) | **Done** — shipped in #128 (`tools/tenant_id.py`) |
| 1 | [0018](0018-device-credentials-by-reference.md) §7c prerequisite: a declared `kind`/capability on `CredentialResolver` | The smallest unit in the set, and three behaviours — cache, breaker, metrics — are all blocked behind it. Today the resolver exposes only `backend: str`, and none of the three may branch on `backend.startswith("files:")` |
| 2 | [0023](0023-gateway-break-glass-attribution.md) | Closes a gap in **shipped** code, depends on nothing else here, and [0017](0017-provider-authority-is-delegated.md) §4 cannot be satisfied until it lands |
| 3 | [0018](0018-device-credentials-by-reference.md) §3: archive exclusion, plus *needs reconnecting* on the device-list projection | Completes the backup simplification; no new dependencies |
| 4 | [0018](0018-device-credentials-by-reference.md) §6: the plan digest | The critical path. Both restore and [0022](0022-agent-initiated-device-writes-are-plan-bound.md) wait on it, and it is specified but not yet built |
| 5 | [0022](0022-agent-initiated-device-writes-are-plan-bound.md) | Directly gated by 4 |
| 6 | [0020](0020-the-device-catalog.md) | The largest single item, and the one that introduces PostgreSQL as a new deployment dependency |
| 7 | [0017](0017-provider-authority-is-delegated.md) | Must follow the catalog — see below |
| 8 | [0021](0021-separate-console-applications.md) | Mostly console work in the UI repository; can run in parallel with 7 |

**Why 0017 sits behind 0020 rather than ahead of it**, despite being the record the other four
follow from: [0020](0020-the-device-catalog.md) must exist before
[0017](0017-provider-authority-is-delegated.md) removes the provider's reach, or there is a
window where the provider cannot help and has no replacement path. That constraint is unchanged
from the original ordering.

**What "every open question closed" does and does not mean.** The design answers were made on
2026-08-20 but only reached the records on 2026-08-21 — the acceptance commit moved the status
lines and nothing else, so fourteen answered questions sat in the files reading as open for a
day. They are now written into each record's `Open questions` section, struck through with the
resolution. **Two remain genuinely open, both deliberately, because both need data that does
not exist yet:** [0018](0018-device-credentials-by-reference.md)'s credential-cache **TTL value**
(networked backends only) and its **plan-digest validity window**. Neither blocks acceptance;
the digest window sits on build item 4 and will want an answer as that work starts. Everything
else in 0007 and 0017–0023 is decided.

**[0024](0024-tenant-provisioning-is-a-request.md) is a prerequisite for 7 and 8**, and is
cited by 0014/0019/0023 in already-shipped or near-term work. It defines the provisioning
workflow those five records assume — ADR-0021 refers to "the provisioning-workflow checklist
gate" as an established mechanism, which until 0024 was established only in a document outside
both repositories. It is not sequenced into the table above because it is a decision to record
rather than a slice to build; the code it implies (a request object, its status machine, its
gates) belongs to the provider console and lands with 8.

[0022](0022-agent-initiated-device-writes-are-plan-bound.md) and
[0023](0023-gateway-break-glass-attribution.md) are later, independent additions — not part of
the five above. 0022 stems from the IBN-controller use case; 0023 was surfaced while reviewing
0017 §4's break-glass requirements against ADR-0007's original, unhardened mechanism. Neither is
part of the tenancy decision, but each attaches to it: 0023 is a prerequisite for 0017 §4, and
0022 is a dependent of 0018 §6.
