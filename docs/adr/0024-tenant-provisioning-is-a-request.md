# ADR-0024: Tenant provisioning is a request the console files and GitOps fulfils

- **Status:** Accepted
- **Date:** 2026-08-21
- **Builds on:** [ADR-0004](0004-single-tenant-per-stack.md) (one stack per tenant),
  [ADR-0013 §10](0013-two-plane-tenancy-and-the-provider-plane.md) (offboarding),
  [ADR-0014](0014-tenant-namespace-naming-and-network-isolation.md) (network isolation, and
  the GitOps precedent this follows), [ADR-0019](0019-opaque-tenant-identity.md) (the
  identifier), [ADR-0017](0017-provider-authority-is-delegated.md) (the provider-access
  tier), [ADR-0021](0021-separate-console-applications.md) (the console domain),
  [ADR-0023](0023-gateway-break-glass-attribution.md) (per-tenant break-glass credentials)

## Context

**Five Accepted ADRs each hang a requirement on "the provisioning workflow," and no record
defines it.**

| ADR | What it assumes provisioning does |
|---|---|
| [0014](0014-tenant-namespace-naming-and-network-isolation.md) | adds the tenant to the Cilium clusterwide list when Tier 2 isolation is required — the base kustomization deliberately does not include `cilium-clusterwide-deny.yaml` |
| [0017](0017-provider-authority-is-delegated.md) | collects the provider-access tier per tenant, pre-selected to Tier 1 |
| [0019](0019-opaque-tenant-identity.md) | mints the identifier, once, at creation |
| [0021](0021-separate-console-applications.md) | fires the provider-console domain gate "when a provisioning request would create the estate's **second** tenant" |
| [0023](0023-gateway-break-glass-attribution.md) | generates and delivers a per-individual break-glass credential out of band |

ADR-0021 refers to "the provisioning-workflow checklist gate" as an established mechanism.
It is established — in a work-in-progress specification that lives in **neither repository**
and whose owning repo is deliberately undecided. So the mechanism five Accepted records
depend on is not version-controlled alongside the code that implements them, and cannot be
reviewed as part of any change that relies on it.

**That is the bookkeeping problem. The design problem underneath it is sharper: provisioning
is where most of this architecture's security properties are established rather than
enforced.** A namespace boundary, a randomly-minted identifier, a Cilium policy, a
per-tenant secret, an access tier — none of these are checked at request time by a running
service. They are true because of what someone did once, at creation. A workflow that
establishes load-bearing properties and exists only as prose is a workflow whose properties
hold by habit.

Two failure modes make this concrete, and neither announces itself:

- **A tenant left off the Cilium clusterwide list fails *safe* but silently under-protected.**
  They still get the namespace-scoped default-deny; they do not get the isolation Tier 2
  promised. Nothing errors. The gap is discovered by an audit, or not at all.
- **A second tenant subdomain appearing under a shared parent domain** is what creates the
  compromised-sibling cookie-forcing risk [ADR-0021 §6](0021-separate-console-applications.md)
  describes. Before that moment there is no sibling and no risk; after it, the risk exists
  whether or not anyone noticed the estate crossed the line.

Both are omissions, not errors. Omissions are not caught by tests, by code review of the
thing being changed, or by a runtime check — only by a gate that must be affirmatively
cleared.

## Decision

**Tenant provisioning is a *request* the console files and a GitOps pipeline fulfils. The
console never provisions a stack directly.**

### 1. Stack creation is an infra concern, and this follows an existing precedent

Creating or deleting a tenant stack is architecturally the same class of action as mutating
the Cilium clusterwide policy, which
[ADR-0014](0014-tenant-namespace-naming-and-network-isolation.md) already placed in GitOps
rather than the live application. The reason applies at least as strongly here: a running
application that can create and destroy tenant stacks holds an authority whose compromise is
unbounded, and it holds it continuously in order to use it rarely.

The console's job is to **request** a stack and later **import** it. It is not given cluster
credentials to apply one.

### 2. The identifier is minted by the system, never typed, and there is exactly one of it

Per [ADR-0019](0019-opaque-tenant-identity.md), the identifier must not be derived from
anything the tenant chooses; server-generation is the only way to guarantee that, and
`tools/tenant_id.py new` is what mints it.

**The same identifier backs the namespace, the console subdomain and the provider-side
registry entry.** Three independently generated values would be three things to keep in
agreement, and the failure of that agreement is silent — a console reachable at a subdomain
that maps to a different tenant's namespace is not a error anything reports. It is one
identifier used three times.

An identifier is **never reissued**, even after a tenant departs
([ADR-0019 §4](0019-opaque-tenant-identity.md)): stale DNS, a cached token and a bookmarked
console must never resolve onto a new tenant.

### 3. The generated artifact is a kustomize overlay, and it is safe to commit

The request produces `deploy/overlays/<tenant-id>/kustomization.yaml`, templated from the
existing `deploy/overlays/tenant-example/` rather than from a new format, with the namespace,
the `mcp.gateway/tenant` label and the patches implied by the request pre-filled. This is an
automation layer over the manual process that overlay already documents — not a replacement
for it, which matters because the manual path must keep working for a Lite or single-tenant
operator who has no console.

### 4. Secrets are a separate out-of-band package and never enter the overlay

The tenant's `gateway-secrets` (Redis password, `MCP_SECRET_KEY`, RBAC keys) and its
per-individual break-glass credentials ([ADR-0023](0023-gateway-break-glass-attribution.md))
are generated as a **separate secrets-bootstrap package**: server-generated, shown once,
delivered outside the GitOps repository.

This reuses the pattern already established for the break-glass credential and the
portable-backup passphrase rather than inventing one. The committable artifact and the secret
material are different objects with different distribution paths, and the moment they are the
same object the GitOps repository becomes a credential store.

### 5. What the request captures

Beyond a display name:

- **Network isolation tier** ([ADR-0014](0014-tenant-namespace-naming-and-network-isolation.md))
  — whether this tenant needs Cilium clusterwide isolation on top of the namespace-scoped
  default-deny that always applies. Determines whether the Tier 2 gate below fires.
- **Provider-access tier** ([ADR-0017 §7](0017-provider-authority-is-delegated.md)) —
  **pre-selected to Tier 1**, the recommendation, adjustable at creation and reconfigurable
  later. It is neither a ceiling nor a floor: Tier 0↔1 is a gateway-side config change in
  either direction. Moving to Tier 2 for the first time additionally requires the tenant's own
  IdP admin to configure federation, which is tracked as a follow-up on the request rather
  than blocking it.
- **Whether this tenant's devices are on private addresses** — sets
  `MCP_ALLOW_PRIVATE_TARGETS` on **both** the gateway and worker workloads. Setting it on one
  lets registration succeed while every subsequent call fails, which presents as a device
  fault rather than a configuration one.
- **Any non-standard device ports** needing the NetworkPolicy allowlist extended (a BMC on
  623, Prism on 9440). Both NetworkPolicies, for the same reason.

⚠️ **The two tiers are unrelated and must not be presented as one axis.** ADR-0014's network
isolation tier and ADR-0017's provider-access tier both use the words "Tier 1" and "Tier 2"
and mean entirely different things. Any interface collapsing them, or any prose using "Tier 2"
unqualified, is a defect.

### 6. Two checklist gates, and "fulfilled" cannot be marked with a box unchecked

Both gates below guard *omissions that fail safe but silently*, which is why neither can be a
documented reminder:

- **Tier 2 network isolation.** Fires per request, when the form indicates it is required.
- **Provider-console domain** ([ADR-0021 §6](0021-separate-console-applications.md)). Fires
  **once**, when a request would create the estate's second or later tenant, and only if the
  provider console is not already on a registrable domain separate from the tenant
  subdomains. A genuinely single-tenant estate never encounters it.

The enforcement is the same in both cases and is the whole point: **a request cannot be
transitioned to fulfilled while a required checklist item is unchecked.** A gate someone can
complete by intending to is not a gate — the same reasoning
[ADR-0023](0023-gateway-break-glass-attribution.md) applies to break-glass custody, where a
runbook line was rejected in favour of an automated check.

### 7. Status progression — "fulfilled" and "active" are different gates

```
requested → file generated → manually deployed (human-asserted) → active (system-verified)
```

**The last two must not collapse into one.** A human reporting that they completed the
deployment steps is a *claim*; the connectivity and health check that follows is a
*confirmation*. This is the same distinction
[ADR-0011 §3](0011-backup-and-restore.md) draws for restore's fail-closed preflight — a gate
rather than a documented assumption — and the same one this project has had to name every
time it conflated the two.

### 8. Deletion is symmetric — mark for offboarding, never teardown

"Delete tenant" in the console means **mark for offboarding**, matching
[ADR-0013 §10](0013-two-plane-tenancy-and-the-provider-plane.md)'s retention handling: the
audit chain survives by crypto-shred, the tenant map entry is tombstoned, and the identifier
and hostname enter their cooldown. Actual infrastructure teardown is a separate, later,
retention-policy-driven pipeline action.

The console holding a button that destroys a tenant's stack synchronously would reintroduce
exactly the authority §1 declines to give it.

### 9. Fulfilment is manual, deliberately, and automation is an increment on this model

The request is filed by the console and fulfilled by a human running the generated overlay
and creating the secrets package. Automating those steps — the console performing the
templating, opening a pull request against the GitOps repository, driving a secrets-manager
integration — is a later increment **on this same request/status model**, not a redesign.

Stating that here is what keeps the manual phase from being read as a temporary shape that
automation will replace. The request object, the gates and the four-state progression are the
design; who executes the middle step is not.

## Consequences

- **Positive:** the mechanism five Accepted ADRs depend on becomes a numbered record in the
  same repository as those ADRs, reviewable in the same pull request as any change that
  relies on it. Two silent-omission failure modes get gates that must be affirmatively
  cleared. The console gains no cluster-mutating authority. The existing overlay and the
  manual path keep working, so a Lite or single-tenant operator is unaffected.
- **Negative / cost:** provisioning a tenant remains a multi-step operation with a human in
  the middle, which is slower than a console button and will be asked about. The request
  object, its status machine and its checklist gates are real state the provider console must
  own and persist. Two distinct meanings of "Tier" now have to be kept apart in every
  interface and every document that mentions either.
- **Follow-ups:** `syncgate-ui-spec.md` §10 becomes a **consumer** of this record — what the
  console renders for each gate and each status — rather than the source of truth for what
  the gates are. The automation increment in §9. Whether the secrets-bootstrap package is
  generated by the console or by a separate tool is unresolved and does not need resolving
  here; §4 fixes only that it is separate from the overlay.

## Alternatives considered

- **Leave it in `syncgate-ui-spec.md`.** Rejected: the document is not in either repository,
  its owning repo is undecided, and five ADRs in *this* repository already cite the mechanism
  it describes. A load-bearing decision cited by five records is the definition of something
  that earns its own numbered record.

- **Put it in the UI repository instead.** Rejected: every ADR that references provisioning
  lives here, and the artifacts it produces — a kustomize overlay, a namespace, a Cilium
  policy entry, a `gateway-secrets` Secret — are gateway-deployment objects. The console is
  where the request is *entered*, which makes it the interface to this decision rather than
  its owner.

- **Let the console provision stacks directly**, holding cluster credentials. Rejected for
  ADR-0014's reason, which applies more strongly here: it is a continuously-held authority
  used rarely, whose compromise creates and destroys tenants. The request/fulfil split costs
  a manual step and removes that authority entirely.

- **Make the checklist items documentation rather than gates.** Rejected: both guard
  omissions that fail *safe but silently*, so nothing surfaces when they are missed. This is
  the failure shape this project has repeatedly chosen to structure away rather than
  remember — the `MCP_SECRET_KEY` startup requirement, restore's digest preflight,
  ADR-0023's automated custody check.

- **One combined "tier" covering both network isolation and provider access.** Rejected:
  they are independent properties that happen to share a vocabulary. Collapsing them is the
  same shape of error as reusing `allow_private_targets` for transport encryption
  (TM-I-05) — one control whose name stops describing what it governs.
