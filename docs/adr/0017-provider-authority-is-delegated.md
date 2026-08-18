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
access to them**, and the credential they present is minted **on the tenant's side of the
boundary** — by the tenant's own stack, or by the tenant's identity provider where it is
capable — never by the provider's.

*Which* of those mints it is a per-tenant deployment choice and is settled in §7. The invariant
is the direction, not the mechanism.

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

### 7. The tenant's IdP is required to do nothing it may not be able to do

§1 says the tenant issues. Read quickly, that sounds like a requirement on the tenant's
identity provider — and if it were, this ADR would not be deployable. ADR-0013 §11b asked a
provider's IdP to recognise a step-up context and inject a custom grant claim, and justified
the ask on the grounds that *the provider controls that choice*. No equivalent justification
exists here. A tenant on basic Google Workspace SSO, or any directory without an Actions or
custom-claims surface, cannot be asked for it.

Worse, the ask was already measured and already failed. §11c exists because **no product
tested would mint that claim without custom code inside its issuance path** — and that was an
IdP under the provider's full control. Carrying the same requirement across the boundary, to a
directory nobody here owns, would not be a slightly harder version of a solved problem. It
would be an unsolved one, made mandatory.

#### The principle that resolves it

> **The platform may require capability of software it ships. It may never require capability
> of a directory it does not own.**

ADR-0013 §11b broke this rule and got away with it because the provider was on both sides.
Under §1 the tenant is on the other side, so the rule binds.

#### What the tenant's IdP is actually needed for

The two things §2 conflates are separable, and only one of them carries authority:

- **The support grant is an object in the tenant's stack**, created through the tenant's
  console, held in the tenant's registry, listed and revoked there. The gateway is both its
  issuer and its verifier — one trust domain, no federation.
- **The tenant's IdP authenticates the tenant administrator** who creates it. That is an
  ordinary OIDC login.

Authority lives in the first. The second is only a login. So the capability floor is:

> **The tenant's IdP must be able to log a tenant administrator into their own console.**

Nothing else. Every directory in the objection's list clears that, and so does a Lite or
embedded deployment with local admin authentication and no IdP at all — which is the sharper
test, and the design passes it.

#### Three tiers, and the floor is universal

How the operator's credential is presented at the wire is a per-tenant choice, not an
architectural fork. All three mint in the same direction:

| | Credential | Requires of the tenant's IdP | Closes |
|---|---|---|---|
| **Tier 0 — floor** | Gateway-minted, short-lived, scoped to the grant | Nothing beyond admin login | The standing-access problem |
| **Tier 1 — recommended** | Same, **sender-constrained**: the operator submits a public key with the request and proves possession per call | Nothing | Theft of the credential in transit or at rest |
| **Tier 2 — capable tenants** | Tenant's IdP mints for the operator as a federated principal, and may attach its own MFA/`acr` policy | Guest federation and claim shaping | Binding to a directory identity the tenant governs |

**Tier 1 is the notable one:** proof-of-possession needs a key pair and a signature, both of
which are ours to implement in code we ship. It buys most of what Tier 2 buys and asks the
tenant's directory for nothing. Requiring capability of shipped software rather than of a
customer's directory is precisely the principle above, applied.

#### Binding without a second trusted issuer

Tier 0 raises the obvious question: a bearer credential is held by whoever holds it, so what
ties it to the named operator? The tempting answer — have the tenant's gateway verify a token
from the *provider's* IdP — is the second-issuer arrangement this ADR exists to remove, and
must not be reached for.

The binding is the **session, not a claim**. The operator raises a request from the provider
console; it appears as pending in the tenant's console; a tenant administrator approves it; and
the credential is returned **only to the session that raised it**. Stealing it therefore costs
the same as compromising that operator's session, and the tenant's gateway never has to
believe anything the provider's IdP said.

The provider's IdP is still what authenticates the operator to the provider console — an
ordinary login, no claim shaping — and its assertion of who they are travels with the request
as attribution, exactly as §2 says: it authorizes nothing.

##### Why the session binding is a different kind of answer

Worth naming precisely, because it is what keeps the fix from being a patch. The claim-based
answer asks the tenant's gateway to **prove who the holder is**, which requires believing an
assertion from the provider's directory — the second issuer, restored. The session binding asks
it to prove something else entirely:

> **Not "prove who you are" — "prove you are still the thing that asked."**

That property needs no claim from anywhere, because both ends of it are already inside the
tenant's stack: the tenant's gateway issued the pending request and the tenant's gateway
delivers against it. Nothing crosses a trust boundary in either direction. It is a different
category of solution rather than a repair to claim verification, and the mechanics below are
load-bearing to it rather than incidental.

##### A pending request that cannot be delivered is lost

If the requesting session ends before the tenant administrator approves — a closed tab, an
expired session, a dropped connection — **the approved grant is discarded and the operator
starts over.** There is no recovery path, no re-delivery, and no way for a later session to
collect it.

This is stated as a decision rather than left to implementation because the pressure to soften
it is predictable and arrives dressed as usability: *the admin already approved, the operator
is right there, let them pick it up.* Any such path needs some way to establish that the later
session belongs to the same operator — which is a claim, from the provider's directory, and the
second issuer walks back in through a UX ticket.

Re-requesting costs one round trip and one approval. That is the correct price, and losing the
grant is the deliberate failure mode.

##### The request identifier is a capability, and must be treated as one

The identifier that binds delivery to one session **is** the security property at the wire, not
plumbing around it. Whoever presents it collects the credential, so it is a capability token
regardless of what it is called, and it carries the requirements of one:

- generated from a CSPRNG with no structure to predict, and wide enough that guessing is not a
  strategy — the same bar as a session identifier, not the bar for a correlation id;
- **not a sequence, timestamp, counter or operator-derived value**, any of which turns an
  offline guess into a fetch of someone else's credential;
- delivered once, to the raising session, and never logged, echoed in an error, or shown in a
  URL where it lands in history and proxy logs;
- expiring on its own short clock, whether or not it is ever approved.

The delivery transport itself is an implementation choice — a held connection or a poll keyed
by the identifier both work — and does not change any of the above, which is exactly why the
identifier's properties are specified here and the transport is not. A guessable identifier
breaks the binding as completely as a forged claim would, by a different route.

##### The operator's name on the approval screen is informational

The tenant administrator approving a request sees *who asked* — a name and an identity the
**provider console** established through its own login. That display is attribution for a human
decision and **carries no cryptographic weight on the tenant's side.** The tenant's gateway does
not verify it, cannot verify it without trusting the provider's directory, and must never be
built as though it had.

Stated plainly because it is the one thing a reader is most likely to mistake for the security
property, for the very good reason that it is what the human is actually looking at when they
click approve. The guarantee comes entirely from session-bound delivery. The name is how the
tenant decides whether to approve; it is not what makes the resulting credential safe.

##### Lite clears the floor test but does not participate

§7's floor is worded to include a Lite or embedded deployment with local admin authentication,
and that is a test of the mechanism's minimalism — it shows the design leans on nothing beyond
an administrator being able to log in.

It is **not** a statement that Lite deployments use any of this. Lite has no provider plane, so
there is no operator to raise a pending request and nothing to delegate to: the flow is
**inapplicable there, not merely unnecessary**, and none of §7 becomes a Lite requirement.

#### Step-up: record it, never require it

A tenant whose IdP cannot express `acr` cannot be made to step up before approving a grant.
Requiring it would reintroduce the capability demand through the back door.

So the grant object **records whether it was created under a step-up-verified session**, and
the tenant's console and audit show that plainly. A tenant with a capable directory gets a
stronger property and can see that they have it; a tenant without one gets an honest record
rather than a silent absence. This is the §11c lesson applied one boundary further out — assert
what is true, never assume the capability was there.

#### This does not reopen ADR-0016

Worth confirming explicitly, because a fallback tier for less-capable tenants is exactly where
a rejected design would creep back in.

ADR-0016's door was **provider-asserted identity honoured by tenant gateways**, plus a console
holding credentials for N stacks and routing between them. Tier 0 has neither. The credential
is minted by the tenant's own stack, is valid only at that stack, expires absolutely, is listed
and revocable in the tenant's console, and is presented by an operator reaching that one
gateway. The provider holds something the tenant issued and can withdraw — which is §1, not a
weakening of it.

**The direction of minting is the invariant.** A tier that changed it would be 0016 regardless
of what it was called; a tier that preserves it is a deployment choice, and the three above
preserve it.

#### The residual, stated plainly

At Tier 0 the tenant is trusting the provider's internal handling — that the approved
credential reached the operator named in the request and stayed with them. The tenant's
controls are the window, the single active grant, the audit and the revoke button; what they do
not have is cryptographic assurance of *which* provider employee used it. Tier 1 narrows this
and Tier 2 closes it.

**The related question is not "individual or shared" — that is already answered.** Provider
operators authenticate individually, through the provider's own OIDC login, and have since §6.
ADR-0012 chose a second real issuer over a shared key precisely because accountable identity
beats an anonymous shared credential. So the open item is not a judgment call about what the
model should be.

**It is whether that individual identity survives the whole chain.** The risk is a component
downstream of the login flattening several operators into one before the tenant's stack ever
sees them — a relay substituting its own credential, a shared service token used for the
federation call. That is the regression ADR-0012 rejected in a BFF-held service-token-per-
provider model, and §7's mechanics are where its shape recurs.

So it is stated as a property to hold and to test, not a decision to make:

> **No component between the provider operator's authenticated session and the record written
> in the tenant's stack may substitute an identity of its own.** Every hop either carries the
> operator's identity or refuses to proceed.

**This needs testing rather than asserting, because the collapse is already one omission away.**
The BFF's gateway client carries a shared admin token as its *client-level default header*, and
a per-request bearer merely overrides it — so a call site that forgets to pass one does not
fail, it succeeds as the shared key. `upstream_bearer` documents that outcome exactly ("recorded
in the tenant's audit as a shared key rather than a human") and fails closed for provider-plane
sessions. That guard is correct and it is a guard: the safe behaviour is asserted at a decision
point rather than produced by construction, which is the same shape as a bound that must be
remembered per call site.

The test therefore has to be end-to-end and adversarial in the specific way that matters: **two
distinct operators, two sessions, and an assertion that the tenant's audit chain distinguishes
them** — never that each hop was individually written correctly, which is what a unit test of
the relay would prove and is not the property.

§4's break-glass keys are the one place the answer is genuinely "shared" today
(`MCP_ADMIN_KEY`, ADR-0007), and that is a gap in the same property rather than a separate
question. It belongs to the hardening track named in §4, which should not be deferred
independently of this.

### 8. Revocation tries to stop work in flight; expiry does not

ADR-0013's D4 asked what happens to an in-flight call when a grant ends, and the answer for
ordinary expiry — let it finish — is right: a window lapsing means nothing is wrong, and
tearing down a half-completed device call to honour a clock would create failures rather than
prevent them.

**That answer must not be inherited by revocation, and would be if D4 stayed one question.**
A tenant administrator pressing revoke is very often doing it *because something looks wrong
right now* — a suspected compromise, an operator behaving unexpectedly, a session that should
not be open. Letting an in-flight destructive call complete because it had already started
defeats the purpose of having an emergency stop at all.

So the postures differ, deliberately:

| | In-flight work | Why |
|---|---|---|
| **Expiry** | Allowed to complete | Nothing is wrong; the window simply lapsed |
| **Revocation** | **Interrupted where technically possible** | A human is asserting that something *is* wrong |

Revocation cancels the underlying call where the transport allows it, and always stops anything
not yet dispatched. What it cannot do is undo effects already committed at a device — a write
that reached an appliance has happened, and the console must say so rather than implying the
stop was total.

**The default posture is "try to stop", not "let it finish"**, and it is written here because
inertia points the other way: expiry is the common path, its answer is already settled, and
sharing one code path is the obvious implementation. This is the one case where the settled
answer is wrong for a reason expiry never had.

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
- **Positive: the capability demand on identity providers drops to ordinary login** (§7), which
  is a lower bar than ADR-0013 §11b set for an IdP the provider controlled — and that bar was
  already measured too high once, in §11c.
- **Negative: three presentation tiers is a real matrix** to build, document, test and support,
  and a tenant's tier determines what their audit can honestly claim about who acted. Accepted
  because the alternative is a capability requirement that excludes tenants outright.
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

- **Which tier is the shipped default.** §7 answers *what the tiers are*; Tier 0 is the floor
  and Tier 1 is the recommendation, but whether a new tenant starts sender-constrained or is
  upgraded to it deliberately is a product call with a real onboarding cost attached.
- **How identity propagation is proven on an ongoing basis** — §7 fixes the property and the
  shape of the test; whether that is one end-to-end audit assertion in CI or a broader
  no-shared-credential check across relay paths is an implementation question with real
  coverage consequences.
- **Whether the pending-request channel needs its own transport.** §7's binding has the tenant
  console showing a request raised from the provider console, which implies a path between the
  two planes that carries no authority but must still exist and be available. Polling from the
  provider side is the dull answer and is probably right.
- **Which transports can actually be interrupted** — §8 fixes the posture; how much of it is
  achievable depends per upstream, and a device call already committed cannot be recalled. The
  honest reporting of a partial stop is a console question as much as a gateway one.
- **Whether standing consent should have a maximum term** requiring periodic reaffirmation.
  Leaning yes; not decided here because it is a product policy question.
