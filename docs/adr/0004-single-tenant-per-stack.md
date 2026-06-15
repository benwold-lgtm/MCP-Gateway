# ADR-0004: Single-tenant-per-stack

- **Status:** Accepted
- **Date:** 2026-06-11 (Decision D-1 in the findings register)
- **Related findings:** F-01, F-30, F-32, F-33

## Context

A multi-tenant SaaS framing would require in-application tenant isolation: a tenant-scoped
device namespace, per-tenant RBAC, and per-tenant credential/process isolation. The
gateway as built has three structural properties that make a *shared* deployment unsafe
for mutually-distrusting tenants: a flat `hostname` namespace (F-01), global RBAC scopes
(F-01/F-32), and co-located DevicePods sharing decrypted credentials in one worker process
(F-33). Building real in-app tenancy is a large, migration-sensitive effort.

## Decision

The gateway is **single-tenant per stack**. Tenant isolation is a **deployment boundary**,
not an in-app feature: run a **separate stack per tenant**, each with its own Redis,
`MCP_SECRET_KEY`, and RBAC keys. **Rule #1: never co-host tenants in one deployment.**
Identity is established + authorized at the gateway edge and recorded as the audit
`subject`; it is **not** propagated as an isolation control to workers/upstreams (within a
single-tenant trust boundary that is acceptable — F-30 is an audit/attribution
enhancement, not an isolation gate).

## Consequences

- **Positive:** the isolation boundary is the strongest one available (separate processes,
  separate Redis, separate keys) and needs no in-app tenancy code. Simple to reason about.
- **Negative / cost:** no soft multi-tenancy (one stack serving many small tenants);
  per-tenant overhead is a full stack. The flat namespace / global scopes / shared process
  are **accepted** within a stack (F-01/F-32/F-33 → accepted).
- **Important caveat:** a per-tenant stack still must be hardened — **F-23 (fail-open auth)
  and F-24 (Redis auth/TLS) remain full criticals regardless of tenancy** (see
  [ADR-0006](0006-fail-closed-distributed-defaults.md)).
- **Follow-ups:** a future `tenant` claim on `Principal` is the seam if in-app tenancy is
  ever needed. Full rationale + deployment model in [multitenancy.md](../multitenancy.md).

## Alternatives considered

- **Build in-app multi-tenancy** (tenant-scoped namespace + RBAC + process isolation):
  rejected for now — large, migration-sensitive, and the deployment boundary already gives
  a stronger guarantee for the target use case.
- **Document nothing and let operators co-host:** rejected — unsafe by default; the
  constraint must be explicit (rule #1).
