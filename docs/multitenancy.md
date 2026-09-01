# Multitenancy — deployment models & best practices

> ## ⛔ The provider tier is FROZEN (2026-09-01)
>
> **Supported editions are lite and single-tenant.** The provider plane — the device catalog,
> tenant enrolment, the provider console and delegated support grants — is frozen: no new work,
> and **its image is no longer published**. `release-image.yml` still contains the
> `device-mcp-catalog` job, gated behind a manual `publish_catalog` input, so a tag build does
> not push it.
>
> **Frozen, not withdrawn.** Nothing is deleted, `ci.yml` still builds and tests the catalog on
> every PR, and `deploy/kubernetes/catalog/` is untouched. The reason is sequencing, not a
> reversal of ADR-0013: the foundation gets finished before multi-tenancy is layered back onto
> it. Everything below remains accurate about how the tier works, and D-1 below —
> single-tenant-per-stack — is unaffected, because it was always the model the *supported*
> editions use.
>
> A tenant stack has never needed the catalog: the base kustomization excludes it deliberately
> (see its own comment), and a device is registered directly through `POST /devices`. The
> console now hides "Claim from catalog" where no catalog estate exists, rather than offering a
> button that answers `TENANT_ID not configured on this BFF`.


> **Decision D-1.** The Device MCP Gateway is **single-tenant per stack**. It does
> not implement in-application tenant isolation. Isolation between tenants is
> achieved by running a **separate gateway stack per tenant**, not by partitioning
> a shared one. This document explains why, what that means operationally, and the
> rules you must follow to keep tenants isolated.

> **Settled by [ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md) (Accepted,
> 2026-08-11).** Single-tenant-per-stack is **permanent**, not a deferral: in-app tenancy is
> rejected *on merit* rather than on cost — see [Why not in-app
> multitenancy](#why-not-in-app-multitenancy). The "future `tenant` claim on `Principal`" seam
> this document used to describe has been **withdrawn**.
>
> Above the stacks sits a **provider plane** for the party operating many tenants — see [The
> provider plane](#the-provider-plane-operating-many-tenants). ADR-0013 introduced it; what it
> looks like today is set by four later records, and the provider-plane section below reflects
> those rather than ADR-0013's original mechanism:
>
> | | |
> |---|---|
> | [ADR-0017](adr/0017-provider-authority-is-delegated.md) | The **tenant** issues the credential; the provider asks. Deleted act-on-tenant and the elevated grants entirely. |
> | [ADR-0019](adr/0019-opaque-tenant-identity.md) | Tenant identifiers are opaque from birth and never reissued. |
> | [ADR-0020](adr/0020-the-device-catalog.md) | The provider curates device **types** and offers them; the tenant claims. |
> | [ADR-0024](adr/0024-tenant-provisioning-is-a-request.md) | The relationship itself is enrolled by a handshake, and revocable. |

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
  consequence of the default rather than a rule anyone maintains. The namespace carries the
  tenant's *opaque identifier* (`mcp-t-<16 hex>`, minted with `tools/tenant_id.py new`) and
  never the customer's name — a namespace name is not encrypted, so a customer name there
  survives the crypto-shred of [ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md)
  §10 and leaks into every metric label and dashboard in the estate. The identifier is random
  rather than derived from anything, so there is no key to hold and nothing to reverse
  ([ADR-0019](adr/0019-opaque-tenant-identity.md), superseding ADR-0014 §1). There is
  deliberately **no mechanism to open a path between two tenants**. See
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
without a god account that can reach every tenant at once?

[ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md) answered it with a **second
plane**. [ADR-0017](adr/0017-provider-authority-is-delegated.md) then inverted *who issues the
credential*, which is the answer that stands today.

> **What changed, and why this section was rewritten.** ADR-0013's model had the provider
> assert an identity the tenant's gateway was configured to believe, through an
> *act-on-tenant* grant plus separate *elevated* grants for tool invocation and credential
> access. ADR-0017 slice 6 **deleted all of it** — `provider:invoke`, `provider:credentials`
> and act-on-tenant no longer exist in any form. If you have read an older copy of this
> document describing them, that design is gone.

### The invariant: the tenant issues, the provider presents

A provider operator reaches a tenant's data plane **only while that tenant has delegated
access to them**, and the credential is minted **on the tenant's side of the boundary** —
never by the provider's.

The direction is the invariant. It is what makes the rest of this section short: there is no
cross-tenant credential to scope, route, intersect or revoke centrally, because the provider
never holds one.

### How access is obtained

1. A provider operator **raises a support request** against a *named* tenant, with a
   justification and the scopes they need.
2. A tenant administrator **approves or rejects** it in their own console.
3. On approval, the tenant's own stack **mints a support grant** — an absolute expiry, the
   operator's identity for attribution only, and scopes drawn from *the tenant's* vocabulary
   (`devices:read`, `tools:call`, …), never a provider vocabulary.
4. The operator works in **the tenant's own console**, at the tenant's hostname, writing to
   the tenant's audit — the same console that tenant's own staff use.
5. The tenant **revokes** whenever they choose. Revocation is checked on every request, so it
   takes effect on the next one rather than at the next refresh of a cache.

A delegation the tenant cannot see is not delegation. It is listed in their console, lives in
their audit chain, and is revocable there by anyone who could have created it.

### Asking and deciding are different authorities

This is the distinction ADR-0017 §7a and §7b add, and it only became visible once the two
planes were first deployed as separate processes.

| Scope | Plane | What it permits |
|---|---|---|
| `support:request` | held by the provider, on the tenant's gateway | Raise a request and poll **its own** outcome. Reads nothing, writes nothing, decides nothing. |
| `support:administer` | the tenant's own admins | Approve, reject, list and revoke — and administer enrolment (below). |

The narrowness of `support:request` is the point: a provider must be able to *ask* without
that being a foothold. **Asking is not an authority over anything**, so a credential that can
only ask is safe to hold permanently.

On the provider's own side, `provider:admin` and `provider:monitor` decide who may ask:

- **`provider:admin`** is deliberately unconstrained in *what* it may request. What an admin
  may ask for is already bounded by two stronger things — the tenant's own RBAC, and a human
  reading the request and deciding.
- **`provider:monitor`** may raise **read-only scopes only**, and this is enforced in the BFF
  rather than in the console. A browser is not a gate: narrowing a checkbox list without a
  server-side check would be decoration, and a hand-made request would carry whatever it
  liked. (That exact drift shipped once and was caught by signing in as a read-only operator.)

### Standing consent, for the 3am case

A customer with nobody available to approve a session at 3am is a real operational problem,
and refusing to solve it pushes the solution somewhere worse — a shared credential, a bypass,
an undocumented key.

So a tenant may enable **standing consent**: grants of a named scope may be self-issued by an
identified provider operator without per-session approval. It is **not a different mechanism,
only a different trigger** — still minted by the tenant's stack, still absolutely expiring,
still naming the operator, still revocable mid-session, and still appearing in the tenant's
audit exactly as an approved grant would. A provider cannot enable it, and cannot tell whether
it is enabled except by trying.

### Break-glass is the only unilateral path, and it is loud

Some failures leave a tenant unable to delegate anything — a broken IdP, a wedged stack, an
expired certificate on the console itself. Pretending otherwise produces an undocumented path
rather than no path. So break-glass remains, with four properties that keep it a last resort:

- credentials generated at deploy time and held in the provider's secret store, never in
  configuration;
- use emits a **high-severity event in the tenant's audit chain** plus a notification they
  receive — not a log line they may one day read;
- rate-limited and expiring, so it cannot become an operating mode;
- it grants the tenant's **own** admin scopes. There is no larger provider capability to hold.

### The relationship itself is established, and revocable

Everything above assumes the provider and tenant are already related.
[ADR-0024](adr/0024-tenant-provisioning-is-a-request.md) §10/§11 makes that relationship an
object too, rather than a matter of configuration on both sides:

- a tenant administrator **issues a one-time invitation** in their own console and hands it
  over out of band, along with their gateway address and tenant id;
- the provider **redeems** it, which in one act records the tenant, issues that tenant's
  catalog credential, verifies the gateway reports the tenant the provider minted for, and
  receives the provider's own standing `support:request` credential;
- the tenant **revokes the enrolment** whenever they choose, which is the only control the
  relationship has — §10 chose revocation over expiry, on the grounds that an expiring
  supplier relationship fails closed at the worst possible moment.

Because revocation is the only control, the tenant's console shows every live enrolment with
**when it was last used**, sourced from real authenticated requests rather than self-reported.
A dormant supplier relationship is discoverable by looking, and by nothing else.

### What the provider sees without asking

**Estate-wide observability stays on the metrics plane** ([ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md)
§7), and delegation makes that *more* important, not less: with the data plane requiring a
tenant's involvement, the metrics plane is the only thing a provider sees unaided, so it has
to be good enough to run an estate from.

An estate-wide view is **never** built by querying N tenant APIs with a credential. If the
metrics plane cannot serve a view someone wants, that gets its own ADR with the view named.

The provider console is therefore an estate **overview and catalog** tool
([ADR-0020](adr/0020-the-device-catalog.md)), not a remote control. The catalog is
provider-plane storage: the provider curates device *types* and offers them to named tenants;
a tenant **claims** one into their own registry. An assignment is an offer, never a write into
anyone's registry.

A curated type carries facts about the **product** — its transport, spec path, fingerprint
policy, where its API key goes, what request rate it tolerates. It never carries the tenant's
half: the address and the credential are the tenant's to supply, and the rate limit is a
recommendation that constrains nothing, because a provider enforcing a limit on the tenant's
own gateway would reach across the boundary this whole document is about.

### Tenants see provider activity in their own audit

Every act by a *human* provider principal is surfaced — **including reads**, because "has
someone been looking at my system" is exactly the question being asked — with the actor
pseudonymized at write time as a stable handle. Automated platform operations are not provider
acts and are not surfaced.

### Offboarding

A departed tenant's provider-side audit content is encrypted under a key unique to them;
destroying that key at offboarding leaves the hash chain verifiable while making the content
unrecoverable. ADR-0011 backups are inside the shred.

Tenant identifiers are **opaque from birth and never reissued**
([ADR-0019](adr/0019-opaque-tenant-identity.md)) — not even after a tenant departs — so
a stale bookmark or a cached token can never resolve onto a different tenant. A per-tenant
hostname is likewise never reissued; a tombstone refuses the name forever.

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
