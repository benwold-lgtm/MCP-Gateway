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
| [0007](0007-federated-identity-oidc-and-gateway-rbac.md) | Federated identity (OIDC) + break-glass local keys; gateway owns RBAC | Proposed |
| [0008](0008-fleet-sessions.md) | Fleet MCP sessions — aggregate multiple devices into one client-facing session | Accepted |
| [0009](0009-mcp-passthrough.md) | MCP passthrough — a remote MCP server is a device, not a second entity | Accepted |
| [0010](0010-tool-derived-request-headers.md) | Tool-derived request headers — adopt SEP-2243 for OpenAPI, exclude passthrough permanently | Accepted |
| [0011](0011-backup-and-restore.md) | Backup/restore — ciphertext archives by default, portable export behind its own scope | Accepted |
| [0012](0012-federation-credential-model.md) | Credential model for BFF provider federation — preserve per-user relay, BFF audit first | Proposed |
| [0013](0013-two-plane-tenancy-and-the-provider-plane.md) | Two-plane tenancy — isolated tenant stacks, and a provider plane above them | Accepted |
| [0014](0014-tenant-namespace-naming-and-network-isolation.md) | Tenant namespace naming (pseudonymous, deterministic) + default-deny network isolation between tenants | Accepted |
| [0015](0015-endpoint-fingerprinting.md) | Endpoint fingerprinting — pin TLS SPKI + declared identity, warn on change, opt-in fail-closed | Accepted |
| [0016](0016-reaching-many-tenant-gateways.md) | Reaching many tenant gateways — routing, not fan-out | **Rejected** — superseded before acceptance by [0017](0017-provider-authority-is-delegated.md)–[0021](0021-separate-console-applications.md); kept for its rejected alternatives |
| [0017](0017-provider-authority-is-delegated.md) | Provider authority over a tenant is **delegated by that tenant**, never asserted by the provider — supersedes [0013](0013-two-plane-tenancy-and-the-provider-plane.md) §4/§5a/§6/§8/§11 | Proposed |
| [0018](0018-device-credentials-by-reference.md) | Device credentials held **by reference**, never at rest in the gateway — supersedes most of [0011](0011-backup-and-restore.md) | Proposed |
| [0019](0019-opaque-tenant-identity.md) | The tenant identifier is **opaque from birth** — supersedes [0014](0014-tenant-namespace-naming-and-network-isolation.md) §1 | Proposed |
| [0020](0020-the-device-catalog.md) | The provider's write path is a **catalog**; tenants claim from it — device types *and* provider-operated services. Answers D2 | Proposed |
| [0021](0021-separate-console-applications.md) | Provider and tenant consoles are **separate applications** — supersedes [0013](0013-two-plane-tenancy-and-the-provider-plane.md) §3 as a runtime property | Proposed |

When you add an ADR: copy the template, take the next number, set status `Proposed`, and
add a row here. Flip to `Accepted` when merged.

**0017–0021 are one decision in five records.** They reorient the tenancy model on a single
principle — *the provider holds less and reaches less* — and each supersedes a different part
of what came before. Read [0017](0017-provider-authority-is-delegated.md) first; the other
four follow from it. Build order is **0019 → 0018 → 0020 → 0017 → 0021**, which is not the
order of leverage: [0020](0020-the-device-catalog.md) must exist before
[0017](0017-provider-authority-is-delegated.md) removes the provider's reach, or there is a
window where the provider cannot help and has no replacement path.
