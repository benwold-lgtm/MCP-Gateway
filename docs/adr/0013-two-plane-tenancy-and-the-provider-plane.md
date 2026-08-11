# ADR-0013: Two-plane tenancy — isolated tenant stacks, and a provider plane above them

- **Status:** Proposed
- **Date:** 2026-08-11
- **Related findings:** F-01 (no in-app tenant isolation), F-30 (end-to-end identity),
  F-32 (global RBAC scopes), F-57 (hash-chained audit)
- **Builds on:** [ADR-0004](0004-single-tenant-per-stack.md) (one stack per tenant),
  [ADR-0007](0007-federated-identity-oidc-and-gateway-rbac.md) (OIDC, gateway owns RBAC),
  [ADR-0012](0012-federation-credential-model.md) (BFF federation credentials)

## Context

[ADR-0004](0004-single-tenant-per-stack.md) made tenancy a deployment boundary and left a
door open: *"a future `tenant` claim on `Principal` is the seam if in-app tenancy is ever
needed."* That door is now closed deliberately. Running a stack per tenant costs little —
the compute is small next to the isolation it buys — and the separation is the strongest
available short of separate hardware: its own Redis, its own `MCP_SECRET_KEY`, its own
hash-chained audit chain, its own egress policy and NetworkPolicy.

What ADR-0004 did not answer is the operator experience, and
[ADR-0012](0012-federation-credential-model.md) opened it: someone running N tenant stacks
has N consoles and no aggregate view. The proposed **providers UI** is not a convenience
feature for tenants. It is a **manager-of-managers console for the cloud provider** — the
party operating the platform.

That distinction is the whole of this ADR. There are **two populations**, not one:

- A **tenant user** belongs to exactly one tenant, authenticates to that tenant's own IdP,
  and must not be able to learn that any other tenant exists.
- A **provider operator** is the platform's own staff, is cross-tenant by definition, and
  needs mass monitoring and administration across the estate.

Conflating them is how the deployment boundary gets quietly undone. If one console
federates across tenants for *everyone*, every isolation property ADR-0004 buys is capped
by that console's internal separation — and the console becomes the single component whose
compromise is an estate-wide incident.

A second force: the gateway trusts **exactly one** IdP today (`gateway.oidc.issuer` and
`audience` are single required strings, validated at startup in `oidc.py`). Any
cross-tenant identity story has to say what happens to that.

## Decision

Two planes, separated by which IdP authenticated the session, with the plane fixed for the
session's lifetime.

### 1. The tenant plane is single-tenant end to end

Each tenant stack keeps **its own IdP**. A tenant session is bound to exactly one tenant at
login and is never re-pointed. Federation is invisible from inside it — a tenant user's
experience is the single-stack product, unchanged.

**"Not aware of another tenant" is a testable property, not a posture:**

- Another tenant's resource returns **404, never 403**. A 403 confirms existence.
- **Tenant selection at login is an enumeration surface.** Tenants are routed by
  **per-tenant hostname**, which selects the IdP without ever asking the user to name a
  tenant from a list.
- No response, error, metric label, or timing distinguishes "not yours" from "not there".

### 2. The provider plane is a separate population with its own IdP

Provider operators authenticate to the **provider's** IdP, never a tenant's. This plane is
cross-tenant by design; that is its purpose, and it is why it is a different plane rather
than a role inside the tenant one.

### 3. The plane is immutable for the life of a session

`plane` (`tenant` | `provider`) and, for tenant sessions, exactly one `tenant_id`, are set
**at login from which IdP authenticated the user** and are never taken from a request
parameter and never mutated. A tenant session cannot acquire provider authority by any
in-session path.

Immutability prevents escalation. It is not sufficient on its own, so:

### 4. Cross-tenant power is exercised, not held

A provider session does not carry ambient authority over every tenant for eight hours.
Acting on a tenant is a **discrete, audited, time-boxed act** — "act on tenant X" — scoped
to that tenant and recorded on both sides. Standing estate-wide access is what turns one
compromised provider session into an estate-wide incident.

### 5. The provider layer lives in the BFF, not in the gateway's RBAC

The gateway is the per-tenant isolation unit. Teaching every tenant's gateway a "provider"
concept would leak a cross-tenant notion into the one component whose job is not knowing
that other tenants exist — and would compromise the property that a tenant stack is
independently liftable, restorable ([ADR-0011](0011-backup-and-restore.md)) and migratable.

**Provider scopes are BFF scopes.** They separate the two blast radii rather than granting
one lump:

| Scope | Grants |
|---|---|
| `provider:monitor` | Aggregate health and metrics across the estate. Read-only, no tenant data-plane access |
| `provider:admin` | Administrative action within a named tenant, via the act-on-tenant flow above |

### 6. A tenant gateway trusts the provider IdP as a second issuer

`gateway.oidc.issuer` / `audience` become **lists**. Each tenant gateway trusts its own
tenant IdP *and* the provider IdP, mapping provider groups to gateway roles through the
existing `group_roles` table.

The alternative — the provider holding a per-tenant admin API key — works today with no
gateway change, and is rejected because it destroys attribution: the tenant's hash-chained
audit would record `key:admin` rather than which named human acted. That is exactly the
loss [ADR-0012](0012-federation-credential-model.md) argues against for federation
generally, and it applies with more force here, because these are the highest-privilege
actions on the platform.

The justification is worth stating plainly, because it is easy to mistake for a weakening:
**the isolation being built is tenant-from-tenant, not tenant-from-provider.** The provider
operates the stack — they hold the Kubernetes access, the Redis, the `MCP_SECRET_KEY`. A
tenant cannot meaningfully hide from them, and designing as though they could produces a
*worse* outcome: a shared anonymous credential in place of an accountable identity. Adding
the provider IdP as a second issuer does not create access that did not exist; it makes
existing access attributable in the tenant's own audit chain.

### 7. Mass monitoring does not use the tenant API plane

Cross-tenant fleet health is aggregated from the **existing Prometheus metrics plane**,
which already scrapes each gateway's dedicated metrics port. `provider:monitor` therefore
needs no API credential into any tenant, and the MoM console's read surface — the part in
constant use — carries no cross-tenant API authority at all. Only `provider:admin` reaches
the tenant API, and only through a named, audited act.

## Consequences

- **Positive:** the tenant plane is the shipped single-stack product with no new
  cross-tenant surface; the strongest isolation boundary is preserved *and* an operator
  console exists; provider actions appear in the tenant's own tamper-evident audit as named
  humans; the constant-use monitoring path holds no tenant API credentials; blast radius is
  split between monitoring and administration rather than pooled.
- **Negative / cost:**
  - A gateway change: `issuer`/`audience` become lists, with the multi-issuer JWKS handling
    and startup validation that implies. Fail-closed behaviour (ADR-0006) must be preserved
    per issuer.
  - The BFF becomes a security-relevant component in a way it is not today. Its own audit
    (ADR-0012's prerequisite) is now non-negotiable and must record **which tenant** an
    action touched, not only who acted.
  - Per-tenant hostnames mean per-tenant DNS and certificates — real operational fan-out,
    on top of N stacks to upgrade, N secrets to rotate, N backup schedules.
  - Soft multi-tenancy is permanently out of reach. Accepted; it was never the target.
- **Follow-ups:**
  - **BFF audit logging first.** It is a prerequisite for the provider plane, not a
    parallel track.
  - Cross-tenant leakage will most likely appear as a **cache or session key missing a
    tenant discriminator** — the same shape as F-66, the zombie device hash, and the
    manifest-cache lease: code assuming something about a key. This needs a test from the
    first commit of the federation work, because the failure is silent.
  - [multitenancy.md](../multitenancy.md) is revised against this ADR once it is Accepted.
  - The BFF's own registry becomes the **tenant map**, which raises the priority of the
    BFF backup story ADR-0011 deferred.

## Alternatives considered

- **In-app multi-tenancy** (tenant dimension through registry, RBAC and the worker
  credential model): rejected permanently, not merely deferred. It would retrofit a tenant
  discriminator through every layer, and every place one was forgotten would be a silent
  cross-tenant leak — while the deployment boundary already gives a stronger guarantee for
  a cost the operator has judged acceptable. This withdraws ADR-0004's "future `tenant`
  claim on `Principal`" follow-up.
- **One IdP for the whole platform, tenancy as authorization:** rejected. Simpler, and it
  keeps per-user relay working everywhere — but it makes the IdP a cross-tenant component,
  so tenant separation would rest on correct authorization inside a shared identity system
  rather than on the boundary itself. It also makes "tenant A cannot know tenant B exists"
  much harder, since a shared login surface tends to leak the tenant list.
- **A `provider` role inside the gateway's existing RBAC:** rejected. It puts a
  cross-tenant concept inside the per-tenant isolation unit and breaks the property that a
  tenant stack is self-contained.
- **Provider holds a per-tenant admin API key:** rejected — see §6. No gateway change, but
  no attribution either.
- **Ambient cross-tenant authority on a provider session:** rejected. One compromised
  session would become an estate-wide incident, and the audit would show a session rather
  than a decision to act on a particular tenant.

## Open questions

Left open deliberately; this ADR is **Proposed** until they are settled.

1. **Does `provider:admin` map to gateway `admin`, or to something narrower?** A provider
   operator debugging a tenant may not need `tools:call` on that tenant's devices, and tool
   invocation is the most sensitive thing the gateway does.
2. **What is the time box on an act-on-tenant grant**, and does it re-authenticate (step-up)
   or merely re-authorize?
3. **Does a tenant see provider actions in their own audit view?** Recording them is
   settled; surfacing them is a product decision with a real argument on both sides.
4. **Tenant offboarding.** Deleting a stack is easy; what the provider plane retains
   afterwards — audit chain, backups ([ADR-0011](0011-backup-and-restore.md)), the tenant
   map entry — is not, and is partly a legal question.
