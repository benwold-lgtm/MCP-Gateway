# ADR-0004: Single-tenant-per-stack

- **Status:** Accepted — **extended by [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md)** (see Amendment)
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

## Amendment (2026-08-11) — see [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md)

**The decision above is unchanged and is not superseded.** ADR-0013 extends it and settles
what it left open. Recorded here rather than by editing the record, per the
[register's rule](README.md) that an Accepted ADR is immutable.

Two things change in how this record should be read:

1. **Single-tenant-per-stack is now permanent, not provisional.** The Context above framed
   in-app tenancy as "a large, migration-sensitive effort" — i.e. deferred on cost. ADR-0013
   rejects it *on merit*: a tenant discriminator retrofitted through the registry, RBAC and
   worker credential model would make every place one was forgotten a silent cross-tenant
   leak, while the deployment boundary already gives a stronger guarantee. F-01/F-32/F-33
   remain accepted, now on a stronger rationale than "not yet".

2. **The "future `tenant` claim on `Principal`" follow-up is withdrawn.** That seam is not
   the direction. Where a cross-tenant view is genuinely needed — a provider operating many
   tenant stacks — ADR-0013 puts it in a **separate plane above the stacks** (a BFF with its
   own IdP, its own `provider:*` scopes, and per-session immutable plane binding), never in
   a tenant dimension inside one.

One clause below is also refined by ADR-0013 §6. This record says identity "is **not**
propagated as an isolation control to workers/upstreams… within a single-tenant trust
boundary that is acceptable". Still true within a tenant. But a tenant gateway will now
additionally trust the **provider's** IdP as a second issuer, so that provider actions land
in the tenant's own hash-chained audit as named humans rather than as a shared admin key.
That grants no access the provider did not already have as the operator of the stack; it
makes existing access attributable.

## Alternatives considered

- **Build in-app multi-tenancy** (tenant-scoped namespace + RBAC + process isolation):
  rejected for now — large, migration-sensitive, and the deployment boundary already gives
  a stronger guarantee for the target use case.
- **Document nothing and let operators co-host:** rejected — unsafe by default; the
  constraint must be explicit (rule #1).
