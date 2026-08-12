# ADR-0013: Two-plane tenancy — isolated tenant stacks, and a provider plane above them

- **Status:** Accepted
- **Date:** 2026-08-11 (Proposed) · 2026-08-11 (Accepted, on resolving §8–§10)
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

**Provider scopes are BFF scopes.** They separate blast radii rather than granting one lump:

| Scope | Grants | Notably does **not** grant |
|---|---|---|
| `provider:monitor` | Aggregate health and metrics across the estate. Read-only, no tenant data-plane access | Any tenant API access at all |
| `provider:admin` | The everyday debugging grant within a named tenant: device read, configuration, governance and tool-change history, lease/claim management | `tools:call`; any credential-bearing read |
| `provider:invoke` | **Elevated.** Invoke a tool against a named tenant's live device | — |
| `provider:credentials` | **Elevated.** Credential-bearing access to a named tenant — in practice `backup:read` / `backup:export-portable` | — |

### 5a. `provider:admin` does not map to gateway `admin`

Mapping it onto the tenant gateway's full `admin` role would break §4 at the one point
where it matters most. **Tool invocation is the most consequential thing the gateway does** —
it is why the F-25 header denylist exists, why passthrough permanently excludes
`x-mcp-header` ([ADR-0010](0010-tool-derived-request-headers.md)), and why the egress policy
is guarded on every hop. A support engineer debugging a tenant's device configuration has an
everyday need for reads, config, and governance history; they very rarely need to actuate
the customer's physical hardware to do that job. Bundling the rare case into the common role
means every routine debugging session silently carries standing authority to actuate real
equipment.

So the two **elevated** grants above are separate, each **time-boxed, individually
justified, and emitting its own audit event** — distinct from the act-on-tenant record that
opened the session's access to that tenant at all. This is not a new principle. It is §4's
"named audited act, never ambient" applied one level down, to scope design rather than plane
design; being inconsistent about it here is what would make the rest of this ADR's reasoning
decorative.

### 5b. Credential visibility is the same question as tool invocation

`provider:credentials` exists because the naive answer — "the device API never returns
credentials, so there is nothing to carve out" — is true and irrelevant. `auth_config` is
indeed never projected into any response model. The exposure is
[ADR-0011](0011-backup-and-restore.md) backup export, and for the **provider** it is worse
than it looks for a tenant:

> A ciphertext archive protects against someone who holds the archive but not the key. The
> provider holds the key — `MCP_SECRET_KEY` lives in a Kubernetes secret they operate. So
> **for the provider plane, `backup:read` and `backup:export-portable` are equally a
> credential dump**, and the ciphertext/portable distinction that carries ADR-0011's safety
> argument for tenants carries none of it here.

Therefore no `backup:*` scope sits inside `provider:admin` at any level.

**An honest limit on this carve-out.** `provider:admin` includes device configuration, and
`devices:write` is transitively a credential-disclosure path on any stack: repoint a
device's `base_url` at a host you control and the pod authenticates to it. That is a
property of `devices:write` generally — a tenant's own admin can do it too — not something
this split introduces. It does mean the carve-out **raises the bar and creates a signal
rather than erecting a barrier**: the control that actually bites is the audit record, where
a `base_url` change to an unfamiliar host is a detectable event. Stated here so the
separation is not mistaken for a cryptographic guarantee.

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

#### 6a. The issuer must gate scope eligibility **server-side**

§3's plane-fixing happens in the BFF at login. That is a session-flow guarantee, **not an
enforcement boundary**: once a provider-plane token is minted it can be replayed straight at
a tenant gateway's API with the BFF nowhere in the path. So the gateway must independently
bind **issuer identity → eligible scope set**, and refuse a provider-issuer token presented
for tenant-scoped endpoints exactly as it refuses the converse. Login-time plane-fixing
guides the UI; the gateway is what enforces it.

This has a concrete implementation consequence. `gateway.oidc.group_roles` is a **single
flat `dict[str, str]` today**, consulted for whichever token arrives. Kept flat across two
issuers it is a confused-deputy and a direct privilege-escalation primitive:

> A tenant's own IdP administrator creates a group named whatever the provider mapping keys
> on, puts themselves in it, and is handed provider-level scopes by their own gateway.

`group_roles` therefore becomes **per-issuer**, with no shared or fallback mapping — an
unmapped (issuer, group) pair grants nothing. The elevated scopes of §5 must additionally be
unreachable from *any* tenant-issuer group, whatever it is called.

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
    per issuer, and `group_roles` becomes per-issuer with no shared fallback (§6a).
  - **⚠️ One provider issuer is trusted by every tenant gateway simultaneously, so a
    compromised provider-plane account has a blast radius spanning the whole estate at
    once.** The accountable-identity trade-off in §6 is still the right one — the
    alternative is the same reach with no attribution — but it concentrates risk in the
    provider IdP and raises the bar on protecting *provider-plane* sessions specifically:
    shorter token lifetimes than the tenant plane, MFA, tighter concurrent-session limits.
    Flagged rather than solved; it is a provider-plane hardening question, not a tenancy-model
    one, and does not belong in this ADR's decision.
  - The BFF becomes a security-relevant component in a way it is not today. Its own audit
    (ADR-0012's prerequisite) is now non-negotiable and must record **which tenant** an
    action touched, not only who acted.
  - Per-tenant hostnames mean per-tenant DNS and certificates — real operational fan-out,
    on top of N stacks to upgrade, N secrets to rotate, N backup schedules.
  - Soft multi-tenancy is permanently out of reach. Accepted; it was never the target.
  - **Grant lifetimes (§8) are machinery, not a policy file.** Absolute expiry, a step-up
    flow the IdP must actually support, single-use semantics for `provider:credentials`, and
    enforcement that a session holds exactly one act-on-tenant grant. The last of those is
    the easiest to omit and the one that silently restores what §4 forbids.
  - **Pseudonymization at write time (§9) constrains the audit writer's shape**, not its
    presentation layer: the mapping from provider principal to stable handle has to exist
    before the first record is written, because the chain cannot be rewritten afterwards.
  - **Per-tenant content keys (§10) add a key-management surface** whose failure mode is
    losing readability of your own audit. Destroying the wrong key is unrecoverable by
    design, which is the property being bought — and the reason it needs the same care as
    `MCP_SECRET_KEY`.
- **Follow-ups:**
  - **BFF audit logging first.** It is a prerequisite for the provider plane, not a
    parallel track — and §9 and §10 are prerequisites of *it*: the writer must pseudonymize
    at write time and encrypt per-tenant content under a per-tenant key from its first
    record. Retrofitting either into a hash chain is not possible.
  - Cross-tenant leakage will most likely appear as a **cache or session key missing a
    tenant discriminator** — the same shape as F-66, the zombie device hash, and the
    manifest-cache lease: code assuming something about a key. This needs a test from the
    first commit of the federation work, because the failure is silent.
  - ~~[multitenancy.md](../multitenancy.md) is revised against this ADR once it is
    Accepted.~~ ✅ Done on acceptance.
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
- **`provider:admin` as an alias for the gateway's `admin` role:** rejected — §5a. Simplest
  to implement and the one that would have quietly undone §4, since `admin` carries
  `tools:call` and `backup:*`.
- **Relying on the BFF's login-time plane-fixing as the enforcement point:** rejected —
  §6a. It is a property of one code path, and a minted token does not have to travel that
  path.
- **Provider holds a per-tenant admin API key:** rejected — see §6. No gateway change, but
  no attribution either.
- **Ambient cross-tenant authority on a provider session:** rejected. One compromised
  session would become an estate-wide incident, and the audit would show a session rather
  than a decision to act on a particular tenant.

## Resolved questions

The three questions this ADR was Proposed pending are settled below (2026-08-11), which is
what moves it to Accepted.

### 8. Grant lifetimes are absolute, and the elevated grants step up

**All windows are absolute, never sliding.** A sliding window renews on activity, so a
stolen session that keeps working never expires — which is exactly an attacker's behaviour
profile. Absolute windows bound the damage independently of how busy the thief is.

| Grant | Window | Re-entry |
|---|---|---|
| act-on-tenant | 60 min, absolute | **Re-authorize** — assert the tenant and a justification; no re-proof of identity |
| `provider:invoke` | 15 min, absolute | **Step-up** — re-prove identity |
| `provider:credentials` | **Single use** — one operation | **Step-up** |

Durations are configuration, not constants; the *relationships* are the decision.

**Step-up only where a stolen session gets cashed out.** The two elevated grants are the
points where a compromised provider session converts into real damage: actuating a
customer's hardware, or walking away with their credentials. Act-on-tenant is the everyday
motion of support work, and putting step-up there would fire so often it would train people
to approve reflexively — destroying the signal precisely where it needs to mean something.

Three rules without which the table above is decorative:

- **One tenant at a time.** A session holds act-on-tenant for exactly one tenant; acquiring
  another drops the first. Concurrent grants would rebuild ambient estate-wide authority by
  accumulation, which is §4 defeated in detail rather than honoured.
- **Renewal is a new act, not an extension** — new justification, new audit record. A
  renewal that merely pushes the expiry out is a sliding window with extra steps.
- **The grant gates initiation, not completion.** A tool call that outlives its window
  finishes; it simply cannot start another. Killing work in flight would make operators
  avoid short windows, and the window is the control.

### 9. A tenant sees every *human* provider act, with the actor pseudonymized

Recording was never in question (§4, §6). Surfacing is, and the answer is yes — with the
dividing line drawn between **human and automated**, not between read and write.

A customer asking "has anyone at the provider been in my system?" means a person. Routine
health polling by the platform is not a provider act and does not belong in a tenant's audit
view. Conversely, a *read* by a human support engineer is exactly what they are asking
about, so a read/write split would omit the thing that matters while still admitting noise.
Elevated acts are highlighted; routine ones collapse by default — noise is a presentation
problem, not a reason to withhold.

**The actor is pseudonymized at *write* time, and this is not a UI concern.** The record
lands in the tenant's own hash-chained audit (§6), so anything written in the clear is
readable by anyone who can read the chain, whatever a console chooses to render — and a
hash-chained record cannot be retroactively redacted without breaking verification for
everything after it. A stable per-person handle (consistent across acts, so a tenant can see
"the same engineer, three times") satisfies the transparency need without exposing
individual staff to customer targeting, which is not a decision that can be walked back once
it is in an immutable chain.

**This binds the BFF audit writer**, which therefore cannot be built before this decision —
it is a prerequisite of that work, not a follow-up to it.

### 10. Offboarding: crypto-shred the content, tombstone the name

A departed tenant's own chain dies with their stack, which is easy. The hard part is the
**provider-side** chain, which necessarily spans tenants: removing one tenant's entries
breaks verification for every entry after them.

**Per-tenant content keys resolve this without choosing between the two goods.** Each
tenant's provider-side audit content is encrypted under a key unique to that tenant; at
offboarding the key is destroyed. The hashes are untouched, so the chain still verifies end
to end, while the content is unrecoverable. Immutability and erasure stop being in tension.

Two consequences to implement deliberately:

- **[ADR-0011](0011-backup-and-restore.md) archives of a departed tenant are still that
  tenant's credentials** and belong *inside* the shred. A backup expiring on its own
  independent schedule is a hole straight through this decision.
- **A per-tenant hostname is never reissued.** Stale DNS, cached tokens and bookmarked
  consoles from the departed tenant would otherwise resolve onto a *new* tenant's stack.
  Retain a tombstone — enough to refuse the name forever, and nothing else.

The retention period before the key is destroyed, and its interaction with legal hold,
builds on **F-58** and is a contractual question rather than an architectural one.

**Settled since first draft** (recorded so the reasoning is not re-litigated):

- *"Does `provider:admin` map to gateway `admin`?"* — **No.** See §5a. It is a genuinely
  narrower composite, and `tools:call` is carved out into its own elevated grant.
- *"Does `provider:admin` ever see decrypted device credentials?"* — **No.** See §5b, and
  note that for the provider a *ciphertext* archive is a credential dump too, because they
  hold the key.
