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
| [0004](0004-single-tenant-per-stack.md) | Single-tenant-per-stack — tenancy by deployment boundary, not in-app isolation (D-1) | Accepted |
| [0005](0005-at-least-once-with-idempotency-guard.md) | At-least-once stream delivery + an at-most-once idempotency guard for writes | Accepted |
| [0006](0006-fail-closed-distributed-defaults.md) | Fail-closed security gates in distributed mode (auth + Redis) | Accepted |
| [0007](0007-federated-identity-oidc-and-gateway-rbac.md) | Federated identity (OIDC) + break-glass local keys; gateway owns RBAC | Proposed |
| [0008](0008-fleet-sessions.md) | Fleet MCP sessions — aggregate multiple devices into one client-facing session | Accepted |

When you add an ADR: copy the template, take the next number, set status `Proposed`, and
add a row here. Flip to `Accepted` when merged.
