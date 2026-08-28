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

### 10. Connecting the tenant to the provider is an enrolment, and an enrolment does not expire (amendment, 2026-08-28)

> **Not built.** This section records a decision. Today the connection is made by editing
> config on both sides by hand; nothing here is implemented.

**Found by standing up the estate's second tenant** — the first time this record's subject
matter was executed rather than described.

#### What this record did not say

§5 captures a **provider-access tier** as a field on the request form, and §9 says fulfilment
is manual. Between them they imply that connecting a tenant to its provider is a setting.
It is not. It is state on **both sides**, and neither side can produce it alone:

| Side | Must hold |
|---|---|
| The tenant's gateway | an RBAC entry for the provider, carrying `support:request` and nothing else (ADR-0017 §7a) |
| The provider's console | the tenant's id, display name and gateway URL, in its registry |
| The tenant's console | the catalog's address, a credential for it, and its own `TENANT_ID` |

None of that appears on the request form, and none of it is derivable from the other side.

#### Measured: nine steps, and the failure modes matter more than the list

Recorded because the *shape* of each failure is what a mechanism has to defend against, and
three of these are silent:

| # | Step | If wrong |
|---|---|---|
| 1 | Mint the tenant id (§2) | irreversible; never reissued |
| 2 | Choose non-colliding ingress ports | reads as a routing fault |
| 3 | Give the tenant its **own** IdP application **and its own group names** | 🔇 sharing them makes another tenant's admin an admin here — and it *works*, for the wrong users |
| 4 | Point `group_roles` at those names | 🔇 authenticates, zero scopes, 403 everywhere — reads as a directory problem |
| 5 | Mint the provider's `support-requester` token | **gateway refuses to start, naming the field** — the model failure mode |
| 6 | Generate the console's own secrets | console cannot start |
| 7 | Install the ingress controller | 🔇 **no connection at all**, while ports listen and Ingress objects exist — every symptom says "deployed" |
| 8 | Create the device credential (a directory user *and* a policy binding it a role) | a user without the binding is refused everything |
| 9 | Wire the catalog: address, credential, `TENANT_ID`, **and an egress port** | 🔇 times out; reads as "the catalog is down" while it is healthy |

Step 5 is the one to imitate. It fails **loudly, at startup, naming the missing field**, because
ADR-0017 §7a made the entry explicit rather than optional. Steps 3, 4, 7 and 9 fail quietly, and
two of them were defects in the tooling itself, found only because a *second* tenant existed.

#### Decision: a request-and-approve handshake, in §7's direction

Model it on [ADR-0017 §7](0017-provider-authority-is-delegated.md): **the provider asks, and a
human on the tenant's side decides.** Nothing about enrolment may be asserted by the provider,
for the same reason nothing about access may be — §1 of that record is the constraint, and a
provider that could enrol itself would be choosing its own customers.

Approving an enrolment performs, atomically, what nine manual steps do today: the tenant's
gateway gains the `support:request` RBAC entry, the provider's registry gains the tenant, and
the tenant receives the catalog's address and **its own** credential for it.

#### The bootstrap problem, and why the invitation is the thing that expires

There is a chicken-and-egg at the start: a provider cannot raise a request against a tenant's
gateway before it holds a credential to raise one with. Two ways out, and only one is
acceptable.

An **unauthenticated enrolment endpoint** on the tenant's gateway is rejected, for the reason
§7a already rejected an unauthenticated raise route: it converts a closed surface on the
tenant's gateway into an open one, and that trade belongs to the tenant rather than to a
default.

So the tenant issues an **invitation**: a one-time, short-lived code generated in the tenant's
own console and handed to the provider out of band. The provider redeems it once; redemption is
what mints the standing credential. The tenant is still the origin of every authority the
provider ends up holding, and no surface is opened to anyone who was not invited.

**The invitation expires. The enrolment it produces does not.** That distinction is the whole
of the next section.

#### Why an enrolment must not expire

ADR-0017's grants are time-boxed, and this deliberately is not. The difference is what the
thing carries.

**A grant carries capability** — read this fleet, invoke that tool. A capability outliving the
reason it was issued is exactly the risk, so it expires, and the window is the control.

**An enrolment carries no capability at all.** The provider's side of it permits one verb:
*ask*. It reads no device, writes nothing, invokes nothing and decides nothing — §7a is
explicit that what a provider holds continuously is standing permission to raise a request. The
tenant's side permits reading what it has itself been offered. Neither is a capability whose
staleness is dangerous.

Given that, an expiry would not be a security control. It would be **a scheduled outage with a
security-shaped name**: on a timer nobody watches, the provider silently loses the ability to be
asked for help, the tenant's catalog goes empty, and the first symptom is a support request that
cannot be raised during whatever incident prompted it. Renewal machinery would then exist solely
to prevent the failure the expiry introduced.

It is also the wrong instrument for the question. "Is this company still our supplier?" is a
commercial fact that changes at a contract boundary, not a clock, and no interval approximates
it. **So the control is revocation, and revocation only:** a tenant administrator ends the
relationship in their own console, immediately, at a moment they choose.

#### What replaces expiry, because something must

An expiry has one virtue worth keeping: it forces a periodic re-examination. Removing it without
replacement leaves a supplier relationship that ended two years ago still live because nobody
remembered. So the requirement transfers rather than disappearing — **visible, not expiring**:

- Every enrolment is listed in the tenant's own console, with who approved it and when.
- Each carries **last-used**, sourced from the audit rather than self-reported, so a dormant
  relationship is discoverable by looking rather than by remembering.
- Revocation is immediate and needs no counterparty. Following §8's reasoning about revoke
  versus expiry: a tenant ending a supplier relationship is very often doing so *because*
  something is wrong right now.

A dormant enrolment should be **easy to find and trivial to end**, which is a stronger property
than one that lapses on a schedule and takes working access with it.

#### This is where ADR-0020 §7a's credential comes from

[ADR-0020 §7a](0020-the-device-catalog.md) requires the catalog to issue **one credential per
tenant** rather than share the provider's. It does not say what mints them, and a per-tenant
credential provisioned by hand is step 9 again with more steps.

Enrolment is the answer: approving one is the moment a tenant first needs catalog access, and
the moment both sides' identities are known. Revoking an enrolment revokes that credential too.
The two records should be built together — §7a states the property, this states the lifecycle,
and neither is complete alone.

#### The property to test

> **Every piece of state the connection depends on is created by approving the enrolment, and
> removed by revoking it.** No step in the nine above may remain something a human does
> separately and correctly.

Test it by revoking: the provider must lose the ability to raise, the tenant's catalog must
close, and **the tenant's own operation must be unaffected** — devices keep working, users keep
signing in. An enrolment that takes the tenant's fleet down when it ends was a dependency, not a
relationship.

#### The shape worth remembering

A record can be accepted, correct, and still silent about the thing that turns out to be hard.
ADR-0024 describes provisioning a tenant thoroughly — the identifier, the overlay, the secrets
package, the checklist gates — and never asks how the tenant and the provider come to know
about each other, because when it was written there was one tenant and the question could not
arise. **The second instance is what makes a relationship visible as a thing needing its own
design**, which is the same lesson ADR-0017 §7a and ADR-0020 §7a each learned on the same day,
in different components.

## Consequences

- **Positive:** the mechanism five Accepted ADRs depend on becomes a numbered record in the
  same repository as those ADRs, reviewable in the same pull request as any change that
  relies on it. Two silent-omission failure modes get gates that must be affirmatively
  cleared. The console gains no cluster-mutating authority. The existing overlay and the
  manual path keep working, so a Lite or single-tenant operator is unaffected.
- **Negative: connecting the tenant to its provider has no mechanism yet** (§10). It is nine
  manual steps spanning two clusters and an identity provider, three of which fail silently,
  and this record described none of them until a second tenant made them visible. §10 records
  the decision — a request-and-approve enrolment that does not expire — and nothing is built.
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
