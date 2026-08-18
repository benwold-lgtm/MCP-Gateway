# ADR-0016: Reaching many tenant gateways from the provider console

- **Status:** **Rejected** — superseded before acceptance by
  [ADR-0017](0017-provider-authority-is-delegated.md) …
  [ADR-0021](0021-separate-console-applications.md)
- **Date:** 2026-08-17
- **Builds on:** [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) §4/§5a/§6/§7,
  [ADR-0014](0014-tenant-namespace-naming-and-network-isolation.md) §1/§3/§4/§6,
  [ADR-0012](0012-federation-credential-model.md)

> ## Why this was not accepted
>
> This ADR answers the question *"how does the provider console reach a customer's gateway?"*
> correctly. The question turned out to be the wrong one.
>
> Writing it made the shape of the problem visible: the routing machinery, the entitlement
> intersection it preserves, the ceiling it depends on and the second trusted issuer beneath
> all of it exist to make it safe for the provider to reach into a tenant's stack holding a
> credential. **ADR-0017 removes the reach instead**, and with it the reason to route.
>
> The record is kept rather than deleted because two of its rejected alternatives remain true
> and would otherwise be re-derived by anyone who revisits this — deriving endpoints from the
> ADR-0014 namespace pseudonym puts `K_ns` in a browser-facing component, and letting the IdP
> assert endpoints turns an identity compromise into a credential redirection. Its finding
> that ADR-0014 needs no change also survives, for the same reason: nothing here was ever
> tenant-to-tenant.
>
> The one decision inside it that carries forward unchanged is **§1: this was never fan-out.**
> Estate-wide reads belong on the metrics plane, and no successor ADR reopens that.


## Context

The provider console is finished as a single-tenant tool. It authenticates provider
operators, authorizes a time-boxed act on one named tenant, elevates through a step-up for
tool invocation and backup, and shows that tenant's fleet, monitoring and registry.

It reaches exactly one gateway. `GATEWAY_URL` is one base URL, `TENANT_ID` names the one
tenant this deployment serves, and `require_role` refuses a provider session whose grant
names anything else. The consequence is visible in the product: the tenant picker lists the
operator's whole directory entitlement and then marks all but one of them **"not served
here — an act is recorded but reaches no devices."** That sentence is a placeholder for this
ADR.

The BFF's own `grants.py` has carried the note since the provider plane was built: *"Reaching
N gateways is slice 3."* This is slice 3.

**The framing in that note is wrong, and correcting it is most of the decision.** "Fan-out"
implies the console talks to many gateways at once. It must not. ADR-0013 §7 rests
cross-tenant fleet health on the **metrics plane** precisely so that `provider:monitor` — the
constant-use read path — holds no tenant API credential at all, and ADR-0014 §4 makes that
scrape the single standing cross-namespace path in the design. A console that queried N
tenant APIs with a credential to draw one dashboard would relocate the estate-wide read path
from the metrics plane back onto the credentialed one, undoing the reason §7 is shaped the
way it is.

So the problem is not fan-out. It is **routing**: given a live act on tenant T, send that one
request to T's gateway instead of to the only gateway this process knows.

## Decision

### 1. Slice 3 is routing, not fan-out

One act, one tenant, one upstream. The console never holds a credentialed conversation with
two tenants' gateways, and no view is built that would require it.

This is not a performance judgement, it is the §4 rule expressed at the transport. §4 says a
session holds act-on-tenant for exactly one tenant *because* accumulation is estate-wide
authority assembled one justified act at a time. A request path able to address N gateways
concurrently is that accumulation available at the network layer regardless of what the
session object says — the grant would be the only thing standing between an operator and the
estate, rather than one of two independent limits.

Aggregate views stay on the metrics plane, where they already are (ADR-0013 §7, ADR-0014 §4).
**If an estate-wide view is ever wanted that the metrics plane genuinely cannot serve, it
gets its own ADR** with the view named, the way ADR-0014 §6 requires of an inter-tenant path.

### 2. The tenant→endpoint binding is provisioning output, read as configuration

The console resolves tenant T to a base URL through a registry written by the provisioning
path — the same GitOps authority that ADR-0014 §3 makes the sole writer of tenant
NetworkPolicies and that creates the namespace in the first place.

It is **not derived** in the console, and it is **not asserted by the IdP**. Both alternatives
are rejected below for reasons that are not stylistic.

The registry is a plain map from tenant identifier to base URL. It carries no credentials:
what the console presents is decided by §3 and is per-operator, not per-tenant.

**Fail closed and fail *specific*.** A tenant absent from the registry is unreachable, and the
refusal says *no route is configured for this tenant* — never *you are not entitled to it*.
Those are different problems with different owners: one is a provisioning gap the provider
fixes, the other is a directory decision. A console that reported the first as the second
would send an operator to argue about entitlement they already have.

### 3. The credential does not change

ADR-0013 §6 already settled what the console presents to a tenant's gateway: the operator's
**own** provider-IdP token, relayed only while a live act-on-tenant grant names that tenant,
and never the tenant stack's admin key. Every tenant gateway already trusts the provider
issuer as a second issuer with a server-side ceiling (§5a/§6a).

Routing changes the destination. It changes nothing about what travels, what authorizes it,
or what the receiving gateway does with it — including ADR-0013 §11c's entitlement
intersection, which stays where it is, on the gateway, for the reason it was put there: the
console is the side that chose the tenant.

**This is what makes slice 3 small.** The hard problems — accountable identity across a
tenancy boundary, a ceiling that survives a compromised console, single-use elevation — were
solved when the plane was built. What is left is a base URL.

### 4. A deployment is either single-tenant or an estate console, never both

`TENANT_ID` and the tenant registry are mutually exclusive, enforced as a **startup refusal**,
in the same place and the same style as the BFF's existing refusal of two IdPs in one process
and its refusal of a widened session cookie.

A tenant-stack BFF sets `TENANT_ID` and no registry, and behaves exactly as it does today —
this ADR must not change the single-tenant product, which is the deployment most installs
are. An estate console sets a registry and no `TENANT_ID`.

Accepting both would mean a process that serves one tenant natively *and* routes to others,
which is the tenant-stack BFF holding cross-tenant machinery — the arrangement ADR-0013 §5
refuses for the gateway and the BFF already refuses for IdPs. The refusal is not a
convenience check; it is the same boundary, at the third place it can be crossed.

### 5. D1 is answered: authorize refuses an unroutable tenant

ADR-0013's open D1 — *should authorizing an act refuse a tenant this deployment cannot
serve?* — was held for this ADR because the answer changes under routing. It does, and the
answer is now **yes**.

Today refusing would be wrong: a single-tenant console legitimately cannot serve anything
else, so refusing would mean the act-on-tenant mechanism only ever accepted one value and the
grant would be decoration. Under a registry the console can distinguish *"I have no route"*
from *"that tenant is not mine to serve"*, and an act that provably reaches nothing is worth
refusing **before** the operator writes a justification into an append-only chain.

The refusal is a capability statement, not an authorization one, and §11c is untouched: the
console still cannot decide that an operator *may* act on a tenant — only that it has
nowhere to send the request. The distinction is testable, and the test is that a tenant
present in the registry is accepted regardless of what the directory said, with the gateway
still refusing it.

### 6. No change to ADR-0014's network model

Checked rather than assumed. ADR-0014 §3's allow table already admits the ingress controller
to a tenant's API on 8000 and calls it *"the only legitimate route to the tenant API."* The
provider console reaching tenant T over T's per-tenant hostname is a client of that route —
the same route the tenant's own operators use.

So slice 3 opens **no new cross-namespace path**, needs no exception, and does not disturb
ADR-0014 §6's absolute inter-tenant deny. Nothing here is tenant→tenant; the console is
provider plane, and per-tenant hostnames with per-tenant DNS and certificates were already
accepted as a consequence in ADR-0013.

Recorded explicitly because the opposite conclusion is the intuitive one — "the console must
reach N namespaces, so the isolation ADR must need an exception" — and a future reader
should find the reasoning rather than reopen §6.

### 7. Failures are per tenant and are never silent

One tenant's gateway being unreachable is that tenant's outage, not the console's. A routing
failure is reported as itself — naming the tenant and the endpoint — and is never rendered as
an empty fleet, because "no devices" and "could not ask" are the two readings an operator
must not have to distinguish by guessing.

This is the same defect class the console has already shipped once: an empty Devices view
that was three wiring faults, and read as an empty tenant.

## Consequences

- **The provider console becomes routing-critical.** A wrong registry entry sends an
  operator's credentialed request to the wrong tenant's gateway. The receiving gateway would
  refuse it — the token's grant claim names a tenant and §11c intersects it — so the failure
  is contained, but it is contained by the *far* side, which is exactly the property worth
  stating rather than relying on quietly.
- **`GATEWAY_URL` stops being one value on the estate console**, so anything that assumed a
  single upstream — the client's connection pool, timeouts, the `/v1` prefix — becomes
  per-tenant. This is the bulk of the implementation.
- **Per-tenant DNS and certificates were already the accepted cost** (ADR-0013), and the
  registry makes them a hard dependency rather than a future one.
- **The BFF's audit must name the tenant on every record**, which ADR-0013 already required
  when the BFF became security-relevant. Under routing it stops being a documentation
  nicety: it is the only record of which estate a request was sent to.
- **Offboarding gains a step.** ADR-0013 §10 tombstones a per-tenant hostname so it is never
  reissued; the registry entry must be removed in the same operation, or the console keeps a
  route to a shredded tenant.
- **The single-tenant product is unchanged**, by §4's construction rather than by care.

## Alternatives considered

**Derive the endpoint from the ADR-0014 namespace pseudonym.** Elegant and deterministic: the
console computes `HMAC(K_ns, "namespace:v1:" || tenant_id)` and knows the namespace without
being told. Rejected because it puts `K_ns` in the console. That key exists to stop a
namespace name being reversed by dictionary attack over a plausible customer list (ADR-0014
§1), and ADR-0014 explicitly warns against reusing key material across pseudonym purposes.
Handing it to a browser-facing, security-relevant, internet-adjacent component trades a real
secret for the convenience of not writing down a map that provisioning already has.

**Let the IdP assert each tenant's endpoint alongside the entitlement claim.** The directory
already names the tenants an operator may act on (§11c), so naming their endpoints looks like
one more claim. Rejected, and this is the alternative most worth recording: it would make the
IdP authoritative for **routing**, so a misconfigured or compromised directory could point an
operator's credentialed request at a host of its choosing. Entitlement and routing have
different trust requirements — one says who may act, the other says where the credential
goes — and a claim that conflates them turns an identity compromise into a credential
redirection.

**A discovery API on some provider-side service.** More moving parts than a map, a new
runtime dependency in the request path, and it answers a question that is static between
provisioning events. ADR-0014 §1 made the same call for namespaces: deterministic or
provisioned, not looked up.

**Keep `TENANT_ID` and let the registry supplement it.** Rejected in §4. It reintroduces the
one process that is both a tenant stack's BFF and an estate console.

## Implementation notes

- The natural shape is a per-tenant `GatewayClient` resolved from the act, replacing the
  single `app.state.gateway`. Connection pools are per-host in httpx anyway, so a small
  cache keyed by tenant is closer to the existing behaviour than it looks.
- `require_role`'s three-part check (§4 of ADR-0013) keeps its shape; only the second part
  changes from *"the grant names this deployment's tenant"* to *"the grant names a tenant
  this deployment can route to."* The credential check is untouched and must stay.
- The startup refusal in §4 belongs beside the existing two in `create_app`, which is now
  the natural home for "this deployment is internally contradictory" checks.
- **The single-tenant path deserves its own regression test rather than trust.** The risk in
  this change is not the new code, it is a tenant-stack deployment quietly acquiring
  estate-console behaviour.

## Open questions

- **D4, inherited from ADR-0013 and still open: what happens to in-flight work when an act
  ends or expires?** Routing sharpens it — an act that expires mid-request now has an
  identified upstream that may already be executing a tool call. Not answered here because
  it is a grant-lifecycle question rather than a routing one, and answering it badly in this
  ADR would bind the wrong decision.
- Whether an estate console should refuse to start when the registry is empty. It is
  arguably a misconfiguration and arguably a valid day-zero state; nothing yet distinguishes
  them.
