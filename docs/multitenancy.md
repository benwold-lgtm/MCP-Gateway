# Multitenancy — deployment models & best practices

> **Decision D-1.** The Device MCP Gateway is **single-tenant per stack**. It does
> not implement in-application tenant isolation. Isolation between tenants is
> achieved by running a **separate gateway stack per tenant**, not by partitioning
> a shared one. This document explains why, what that means operationally, and the
> rules you must follow to keep tenants isolated.

> 🔭 **Pending revision — read
> [ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md) alongside this.**
> Everything below still holds for a tenant stack, which is the only thing this document
> describes. What it does not yet cover is the **provider plane**: a manager-of-managers
> console, above the stacks, with its own IdP and its own `provider:*` scopes, for the party
> operating many tenants. ADR-0013 also makes single-tenant-per-stack **permanent** rather
> than a deferral, and withdraws the "future `tenant` claim" seam this document inherits
> from [ADR-0004](adr/0004-single-tenant-per-stack.md). This page is revised in full once
> ADR-0013 is Accepted — deliberately not twice.

A "tenant" here means a distinct trust/ownership boundary: a customer, a team, or
any set of devices and credentials that must not be visible or controllable across
the boundary.

## Why single-tenant-per-stack

The gateway was designed around a single owner who controls all registered devices.
Three structural properties make a shared, multi-tenant deployment unsafe, and all
three are by design rather than oversights:

| Property | What it means | Finding |
|----------|---------------|---------|
| **Flat device namespace** | Devices are keyed only by `hostname`; there is no tenant dimension. Any two tenants registering the same hostname collide. | F-01 |
| **Global RBAC scopes** | Roles grant scopes (`devices:write`, `tools:call`, …) across **all** devices. There is no per-device or per-owner authorization — any `devices:write` key can mutate or call any device. | F-01 / F-32 |
| **Process-shared credentials** | Co-located DevicePods in one worker process hold their decrypted device credentials in the same address space. A compromised or buggy pod is not memory-isolated from a co-located tenant's secrets. | F-33 |

Rather than retrofit a tenant dimension through the registry, RBAC, and the worker
credential model (a large, migration-sensitive change with its own failure modes),
D-1 makes the deployment boundary the isolation boundary: **one stack, one tenant.**
This is a deliberate, documented constraint — not a temporary limitation.

## The deployment model

Give each tenant its own complete stack. Nothing is shared across the boundary:

```
Tenant A                              Tenant B
┌──────────────────────────────┐     ┌──────────────────────────────┐
│ Gateway replicas             │     │ Gateway replicas             │
│ Worker replicas              │     │ Worker replicas              │
│ Redis (own instance/db)      │     │ Redis (own instance/db)      │
│ MCP_SECRET_KEY  (own key)    │     │ MCP_SECRET_KEY  (own key)    │
│ RBAC keys       (own keys)   │     │ RBAC keys       (own keys)   │
└──────────────────────────────┘     └──────────────────────────────┘
```

Concretely, a per-tenant stack is the unit of isolation when each tenant gets:

- **Its own Redis** (distributed mode) or its own SQLite file (embedded mode). Do
  **not** point two tenants at the same Redis — the registry, assignments, and call
  streams are a single flat namespace (see [Redis AUTH + TLS](#hardening-each-stack)).
- **Its own `MCP_SECRET_KEY`.** Credentials are encrypted at rest, but a shared key
  means either tenant's stack can decrypt the other's secrets. One key per tenant.
- **Its own RBAC keys.** Because scopes are global within a stack, the API keys you
  issue authorize everything in *that* stack — and nothing in another.
- **Its own network boundary / namespace.** In Kubernetes, a namespace per tenant
  with NetworkPolicies; see [docs/kubernetes-architecture.md](kubernetes-architecture.md).

## Best practices (the rules)

1. **Never co-host tenants in one stack.** This is the load-bearing rule. Sharing a
   gateway, worker pool, Redis, or secret key across tenants defeats every isolation
   property above (F-33). If you find yourself issuing per-tenant API keys against a
   single deployment and hoping RBAC keeps them apart — stop; RBAC scopes are global.
2. **One Redis per tenant, locked down.** A shared control plane is a shared blast
   radius. Each tenant's Redis must additionally enforce AUTH + TLS regardless of
   tenancy — that is a baseline requirement, not a multitenancy one.
3. **One secret key per tenant.** Rotate independently
   (see [docs/secret-rotation.md](secret-rotation.md)).
4. **Automate stack provisioning.** Treat "spin up a tenant" as deploying a
   parameterized stack (Helm values / Kustomize overlay), so the boundary is
   reproducible and auditable rather than hand-assembled.
5. **Do not rely on `hostname` uniqueness across tenants.** It is only unique within
   a stack. Two tenants may legitimately register the same device hostname.

## Identity propagation (F-30)

Within a single stack, **identity is established at the gateway and is not propagated
downstream** to workers or upstream device APIs:

- The gateway authenticates the caller and resolves a `Principal{subject, scopes}`.
  The `subject` is recorded in **audit logs** (see [docs/audit-logging.md](audit-logging.md)).
- The authorization decision (scope check) is made **at the gateway edge**. By the
  time a tool call reaches a worker via Redis, it has already been authorized; the
  worker trusts the call stream within the stack's trust boundary.
- Outbound calls to a device authenticate as the **stack** (its configured device
  credentials / client cert), not as the end caller. The device cannot distinguish
  which gateway principal originated a call.

Under D-1 this is acceptable: a single-tenant stack **is** the trust boundary, so the
end-to-end caller identity does not need to cross it to enforce isolation. The value
of propagating identity further is **audit/attribution granularity** (knowing which
principal triggered a specific upstream call), not isolation — so F-30 is an audit
enhancement, not an isolation gate, and is tracked as such.

## Hardening each stack

Single-tenancy removes the *cross-tenant* attack surface; it does **not** remove the
need to secure each stack. Independent of tenancy, every deployment must still:

- Lock down Redis with **AUTH + TLS** (distributed mode) — an unauthenticated Redis
  is full control-plane takeover.
- Set **`MCP_SECRET_KEY`** so credentials are encrypted at rest
  (see [Credential encryption](../README.md#credential-encryption)).
- Terminate **TLS** in front of the gateway (see [README → Security → TLS](../README.md#security)).

See the [Security section of the README](../README.md#security) for the full list.

## Future direction

In-application multitenancy (a tenant dimension on the registry, per-resource
authorization, and per-tenant credential isolation in the worker) is a possible
future extension, not a current capability. The intended seam is the existing
`authenticate() → Principal{subject, scopes}` boundary: a `tenant` claim on the
principal plus tenant-scoped registry keys and authorization would layer on without
re-architecting the routes. Until that exists, **run one stack per tenant.**

### What the cost of that retrofit currently is

The expensive part is not the authorization seam — it is the **flat `hostname` namespace**:
the identity that Redis keys, the SQLite primary key, the `/v1/devices/{hostname}` route
family, client-visible `device://{hostname}` URIs, the consumer-group name and every
per-device metric label are all built from. [ADR-0009](adr/0009-mcp-passthrough.md) carries
the itemised register, kept current as features land, so the price is known rather than
rediscovered.

Two things have already been done to keep it from growing:

- **`shared/keys.py`.** Every Redis key shape and the `device://` URI come from one
  `KeyBuilder` whose `prefix` is `""` today. Adding a tenant prefix is one change instead of
  roughly twenty, each of which could otherwise orphan live control-plane data. The prefix is
  an explicit constructor argument — no ambient or request-scoped scoping, because implicit
  scoping is the part that is hard to audit.
- **MCP passthrough reuses the device entity** rather than adding a second flat-keyed one.
  A remote MCP server is a `DeviceConfig` with a discriminator field, so a future tenant
  dimension threads through one set of keys, routes and metrics rather than two.

Outbound credentials are also, deliberately, not a tenancy problem: the gateway calls an
upstream with **its own stored per-server credential** and `AbstractAuth.apply()` takes no
arguments, so no caller token is propagated. Forwarding one would be actively unsafe here —
in distributed mode the *worker* makes the outbound call, so a forwarded token would have to
travel through a Redis stream every worker reads.
