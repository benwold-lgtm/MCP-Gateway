# Multitenancy — deployment models & best practices

> **Decision D-1.** The Device MCP Gateway is **single-tenant per stack**. It does
> not implement in-application tenant isolation. Isolation between tenants is
> achieved by running a **separate gateway stack per tenant**, not by partitioning
> a shared one. This document explains why, what that means operationally, and the
> rules you must follow to keep tenants isolated.

> **Settled by [ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md) (Accepted,
> 2026-08-11).** Single-tenant-per-stack is **permanent**, not a deferral: in-app tenancy is
> rejected *on merit* rather than on cost — see [Why not in-app
> multitenancy](#why-not-in-app-multitenancy). Above the stacks sits a **provider plane** for
> the party operating many tenants; see [The provider
> plane](#the-provider-plane-operating-many-tenants). The "future `tenant` claim on
> `Principal`" seam this document used to describe has been **withdrawn**.

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
- **Its own network boundary / namespace.** In Kubernetes, a namespace per tenant with a
  **default-deny** NetworkPolicy in both directions, so cross-tenant denial is a
  consequence of the default rather than a rule anyone maintains. The namespace is named
  as a *pseudonym* (`mcp-t-<16 hex>`, via `tools/tenant_namespace.py`) and never after the
  customer — a namespace name is not encrypted, so a customer name there survives the
  crypto-shred of [ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md) §10 and
  leaks into every metric label and dashboard in the estate. There is deliberately **no
  mechanism to open a path between two tenants**. See
  [ADR-0014](adr/0014-tenant-namespace-naming-and-network-isolation.md) and
  [docs/kubernetes-architecture.md](kubernetes-architecture.md).

  ⚠️ **Verify enforcement rather than assuming it.** A CNI that does not implement
  NetworkPolicy accepts every policy and enforces none — `kubectl get netpol` looks
  identical either way. One pod and one `curl` settle it; see
  [testing-gaps.md TG-10](testing-gaps.md) for the probe and the verdicts to expect.

  ⚠️ **Operating an estate additionally requires Tier 2** ([ADR-0014](adr/0014-tenant-namespace-naming-and-network-isolation.md) §8).
  A default-deny NetworkPolicy is undone by a tenant who *creates* a permissive policy in
  their own namespace — no deletion needed, because NetworkPolicy is additive-allow — so on
  its own the boundary is an RBAC guarantee, not a network one. That is fine for a single
  tenant and the wrong shape of guarantee for a customer boundary. Generate the cluster-wide
  deny policies per tenant and check coverage:

  ```bash
  python3 tools/tenant_isolation_policy.py generate --from-cluster | kubectl apply -f -
  python3 tools/tenant_isolation_policy.py check          # exits 1 on an uncovered tenant
  ```

  Regenerate from the same path that creates the namespace. A missed regeneration exposes
  only the uncovered tenant — each policy isolates its own tenant in both directions — but
  that is a bound on the damage, not an excuse to skip `check`.

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

## The provider plane (operating many tenants)

Running one stack per tenant raises an obvious question: who operates the estate, and how,
without a god account that can reach every tenant at once? [ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md)
answers it with a **second plane** rather than a hole in the first.

- **Two populations, two IdPs.** Tenant users authenticate to their tenant's IdP; provider
  staff authenticate to the provider's. **Which IdP authenticated you fixes your plane**, and
  the plane is immutable for the life of the session. There is no "switch to provider mode".
- **Provider scopes live in the BFF, never in a tenant's gateway.** The gateway is the
  per-tenant isolation unit; teaching it a cross-tenant concept would leak tenancy into the
  one component whose job is not knowing other tenants exist.
- **Cross-tenant power is exercised, not held.** Acting on a tenant is a discrete, audited,
  time-boxed act against a *named* tenant — never ambient authority over the estate.
- **`provider:admin` is not the gateway's `admin`.** Tool invocation (`provider:invoke`) and
  credential access (`provider:credentials`) are carved out into separate **elevated** grants,
  because routine debugging should not silently carry standing authority to actuate a
  customer's hardware or walk off with their secrets.

**Grant lifetimes are absolute, never sliding** — a sliding window never expires for an
attacker who keeps working:

| Grant | Window | Re-entry |
|---|---|---|
| act-on-tenant | 60 min | Re-authorize; **one tenant at a time** — acquiring another drops the first |
| `provider:invoke` | 15 min | **Step-up** (re-prove identity) |
| `provider:credentials` | Single use | **Step-up** |

**Tenants see provider activity in their own audit.** Every act by a *human* provider
principal is surfaced — including reads, because "has someone been looking at my system"
is exactly the question being asked — with the actor **pseudonymized at write time** as a
stable handle. Automated platform operations are not provider acts and are not surfaced.

**Offboarding uses per-tenant content keys.** A departed tenant's provider-side audit content
is encrypted under a key unique to them; destroying that key at offboarding leaves the hash
chain verifiable while making the content unrecoverable. ADR-0011 backups are inside the
shred, and a per-tenant hostname is **never reissued** — a tombstone refuses the name forever
so stale DNS or cached tokens cannot land on a new tenant's stack.

Cross-tenant *monitoring* aggregates from Prometheus, so the constant-use read path holds no
tenant API credentials at all.

## Why not in-app multitenancy

This was **rejected on merit, not deferred on cost** (ADR-0013). Retrofitting a tenant
dimension would take the property that makes this design defensible — a tenant boundary you
can point at, which is also a Redis instance, a key, and a namespace — and replace it with a
correctness argument spread across every query, cache key and session. The failure mode
changes from "impossible" to "silent until it isn't."

That said, the price was itemised before the decision was taken, and it is what the decision
weighed:

### What the retrofit would have cost

The expensive part is not the authorization seam — it is the **flat `hostname` namespace**:
the identity that Redis keys, the SQLite primary key, the `/v1/devices/{hostname}` route
family, client-visible `device://{hostname}` URIs, the consumer-group name and every
per-device metric label are all built from. [ADR-0009](adr/0009-mcp-passthrough.md) carries
the itemised register, kept current as features land, so the price is known rather than
rediscovered.

Two things were done to keep that price from growing while the question was open, and both
remain worth having now that it is closed — they are good hygiene independent of tenancy:

- **`shared/keys.py`.** Every Redis key shape and the `device://` URI come from one
  `KeyBuilder` whose `prefix` is `""`. One place to reason about key shape beats roughly
  twenty, each of which could otherwise orphan live control-plane data. The prefix is an
  explicit constructor argument — no ambient or request-scoped scoping, because implicit
  scoping is the part that is hard to audit.
- **MCP passthrough reuses the device entity** rather than adding a second flat-keyed one.
  A remote MCP server is a `DeviceConfig` with a discriminator field, so keys, routes and
  metrics have one shape rather than two.

> **Where cross-tenant leakage would actually show up.** Now that isolation is delivered by
> the provider plane rather than by in-app scoping, the risk moves with it: the likely defect
> is a **cache or session key in the BFF missing a tenant discriminator**. That is the same
> shape as F-66, the zombie device hash and the manifest-cache lease — code assuming
> something about a key — and it fails *silently*. It needs a test from the first commit of
> the federation work, not a review at the end.

Outbound credentials are also, deliberately, not a tenancy problem: the gateway calls an
upstream with **its own stored per-server credential** and `AbstractAuth.apply()` takes no
arguments, so no caller token is propagated. Forwarding one would be actively unsafe here —
in distributed mode the *worker* makes the outbound call, so a forwarded token would have to
travel through a Redis stream every worker reads.
