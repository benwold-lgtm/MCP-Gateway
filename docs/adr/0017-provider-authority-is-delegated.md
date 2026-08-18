# ADR-0017: Provider authority over a tenant is delegated by that tenant, never asserted by the provider

- **Status:** Proposed
- **Date:** 2026-08-17
- **Supersedes:** [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) §4, §5a, §6,
  §6a, §8, §11a–§11d. ADR-0013's §2, §3, §7, §9 and §10 stand.
- **Replaces:** [ADR-0016](0016-reaching-many-tenant-gateways.md) (Rejected)

## Context

ADR-0013 gave the provider plane a coherent design: a second population with its own IdP, a
time-boxed justified act on one named tenant, two step-up-backed elevated grants, a
server-side ceiling on what the plane may reach, and an entitlement intersection so the IdP
rather than the request decides which tenants an operator may touch. It was built, verified
against real identity providers, and works.

It also rests on one arrangement that is worth stating plainly, because everything expensive
follows from it:

> Each tenant's gateway is configured to trust the **provider's** identity provider as a
> second issuer, and to honour grant claims that provider's IdP mints.

Read from the customer's side, that sentence says: *your isolation from other customers
depends on your supplier's identity provider being correctly configured, and on your
supplier's console being uncompromised.* Every control ADR-0013 adds — the ceiling, the
intersection, the single-use consumption identity, the per-issuer configuration — exists to
make that arrangement survivable. They are good controls. They are compensating for the
arrangement rather than replacing it.

The cost is concentrated rather than spread. Five modules carry this design:
`grants.py` and `oidc.py` in the gateway, `grants.py`, `security.py` and `routers/provider.py`
in the BFF. They are **11% of the Python source and 44% of every ADR reference in it** — four
times the repository's average density of load-bearing decisions, in the code where a mistake
is a cross-tenant breach rather than a bug.

## Decision

### 1. The tenant is the only source of authority over the tenant

A provider operator reaches a tenant's data plane **only while that tenant has delegated
access to them**, and the credential they present is minted by the **tenant's** identity
provider, not the provider's.

This inverts ADR-0013 §6. There, the provider asserted an identity that the tenant's gateway
was configured to believe. Here, the tenant issues, and the provider presents what it was
given.

The consequence is that **there is nothing left to intersect.** ADR-0013 §11c exists because
the tenant named in a grant was chosen by the provider's own console — the side inside the
threat model — so the gateway had to check that choice against a directory claim. When the
tenant issues the credential, the tenant *is* the check. Removing §11c is not a relaxation;
the property it enforced is now structural.

### 2. Delegation is an explicit, tenant-visible, expiring object

A **support grant** is created in the tenant's own stack, by a tenant administrator, and it
carries:

- the provider operator's identity, as the provider IdP asserts it (for attribution only —
  it authorizes nothing);
- an absolute expiry, never extended, never renewed in place;
- a scope drawn from the tenant's own vocabulary (`devices:read`, `tools:call`, …), never a
  provider vocabulary;
- the reason it was created, recorded once and never echoed back.

It lives in the tenant's audit chain, is listed in the tenant's console, and is revocable
there at any time by anyone who could have created it. **A delegation the tenant cannot see
is not delegation**, which is the property that distinguishes this from what it replaces.

The mechanism is deliberately the *same shape* as the act-on-tenant grant it supersedes —
absolute window, mandatory justification, one at a time, no renewal in place. That design was
correct. What changes is which side of the boundary mints it.

### 3. Standing consent is a tenant setting, not an architectural exemption

A customer with nobody available to approve a support session at 3am is a real operational
problem, and refusing to solve it would push the solution somewhere worse — a shared
credential, a bypass, an undocumented key.

So a tenant may enable **standing consent**: support grants of a named scope may be
self-issued by an identified provider operator without a per-session approval. It is a
setting in the tenant's console, visible to the tenant, revocable by the tenant, and every
grant issued under it appears in the tenant's audit exactly as an approved one would.

**It is not a different mechanism, only a different trigger.** The credential is still minted
by the tenant's stack, still expires absolutely, still names the operator, and is still
revocable mid-session. A provider cannot enable it, and cannot tell whether it is enabled
except by trying.

### 4. Break-glass is the only unilateral path, and it is loud

Some failures leave a tenant unable to delegate anything — a broken IdP, a wedged stack, an
expired certificate on the console itself. A provider must be able to act, and pretending
otherwise would produce an undocumented path rather than no path.

Break-glass therefore remains, with four properties that make it a last resort rather than a
convenience:

- credentials generated at deploy time and held in the provider's secret store, never in
  configuration;
- use emits a **high-severity audit event in the tenant's chain** and a notification the
  tenant receives, not a log line they may one day read;
- it is rate-limited and expiring, so it cannot become an operating mode;
- it grants the tenant's own admin scopes — there is no separate, larger provider capability
  to hold.

The hardening of this path is a track of its own and is not designed here beyond the
requirement that it exists, is unilateral, and is impossible to use quietly.

### 5. Estate-wide observability stays on the metrics plane, unchanged

ADR-0013 §7 rests cross-tenant fleet health on the metrics plane precisely so the
constant-use provider read path holds no tenant API credential. That is correct and this ADR
does not touch it. It also becomes more important: with delegation required for the data
plane, the metrics plane is the *only* thing a provider sees without a tenant's involvement,
so it must be good enough to run an estate from.

The corollary from ADR-0016 §1 survives its rejection: **an estate-wide view is never built by
querying N tenant APIs with a credential.** If the metrics plane cannot serve a view someone
wants, that gets its own ADR with the view named.

### 6. Cross-tenant routing does not need solving

ADR-0016 existed to route a provider credential to one of N gateways. Under §1 the provider
console holds no credential for a tenant's data plane at all — it holds, at most, a grant the
tenant issued, which is already scoped to that tenant's stack and is presented by the operator
reaching *that* stack's own console.

The provider console becomes an estate **overview and catalog** tool (see
[ADR-0020](0020-the-device-catalog.md)), not a remote control. When an operator needs a
tenant's data plane, they enter that tenant's console with the delegated credential — the same
console that tenant's own staff use, showing the same audit, under the same hostname.

## Consequences

- **Positive: the tenant's isolation no longer depends on the provider's IdP.** This is the
  whole point. A compromise of the provider's identity provider stops being a cross-tenant
  event, because the provider's IdP no longer mints anything a tenant gateway honours.
- **Positive: a large amount of security-critical machinery stops existing** rather than
  moving — the entitlement intersection, the single-use consumption identity, the server-side
  provider ceiling, the second trusted issuer, and per-issuer grant configuration.
- **Positive: the tenant gains a control they did not have** — a list of who can reach their
  stack right now, and a button that ends it.
- **Negative: a provider cannot unilaterally repair a tenant** except through break-glass. On
  the day a customer is down and nobody answers the phone, standing consent softens this but
  does not remove it. Accepted deliberately: the alternative is a standing path that is always
  open in order to be open on the rare day it is needed.
- **Negative: provider support workflow gets slower and more visible**, which is a product
  decision as much as a security one. Some customers will consider the visibility a feature
  and some will consider the friction a defect; the setting in §3 is where that is negotiated.
- **Negative: the tenant console grows an administrative surface it did not have** — issuing,
  listing and revoking support grants, plus the standing-consent setting.
- **Migration is a rewrite of the provider plane's authority layer, not a refactor.** The two
  designs cannot run concurrently against one tenant without reintroducing the arrangement
  this ADR removes, so the cutover is per tenant and one-way.

## Alternatives considered

**Keep ADR-0013 and harden it further.** The controls are good and the implementation is
verified. Rejected because every one of them is compensating for the same arrangement, and
adding a sixth control does not change who the boundary depends on. The measured density —
44% of the codebase's load-bearing decisions in 11% of its code — is what a compensating-control
design looks like from the inside.

**Provider-minted credentials, but with tenant approval recorded out of band.** A contract or
a ticket saying the tenant consented. Rejected: it is the same arrangement with paperwork, and
the gateway still honours a token the provider's IdP made. Consent that is not enforced at the
point of use is documentation.

**Per-tenant provider identities — the provider holds an account in each tenant's IdP.**
Closer to correct, and this is what §1 becomes in practice for tenants who run their own
directory. Rejected as the *general* form because it makes the provider hold N standing
credentials, which is the "hold less" failure rather than the "reach less" one, and because
offboarding then depends on the tenant remembering to delete an account.

**Do nothing until a concrete failure occurs.** The design works, is tested, and no incident
has happened. Rejected because the failure mode is a cross-tenant credential event, which is
not a thing to learn from experience, and because the cost of changing grows with every
feature built on the current authority model.

## Open questions

- **How a support grant is presented at the wire.** The natural implementation is a token the
  tenant's IdP mints on the tenant's behalf, but a tenant-issued API credential held by the
  gateway itself is simpler for tenants without an IdP. Probably both, chosen per tenant.
- **What happens to in-flight work when a grant is revoked mid-session** — ADR-0013's D4,
  still open and now sharper, because revocation is a deliberate act by a person who expects
  it to take effect immediately.
- **Whether standing consent should have a maximum term** requiring periodic reaffirmation.
  Leaning yes; not decided here because it is a product policy question.
