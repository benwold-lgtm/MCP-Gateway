# ADR-0013: Two-plane tenancy — isolated tenant stacks, and a provider plane above them

- **Status:** Accepted · **§4, §5a, §6, §6a, §8, §11a–§11d superseded** by [ADR-0017](0017-provider-authority-is-delegated.md) (2026-08-19); **§5b superseded** by [ADR-0018](0018-device-credentials-by-reference.md) §6
- **Date:** 2026-08-11 (Proposed) · 2026-08-11 (Accepted, on resolving §8–§10)
- **Related findings:** F-01 (no in-app tenant isolation), F-30 (end-to-end identity),
  F-32 (global RBAC scopes), F-57 (hash-chained audit)
- **Builds on:** [ADR-0004](0004-single-tenant-per-stack.md) (one stack per tenant),
  [ADR-0007](0007-federated-identity-oidc-and-gateway-rbac.md) (OIDC, gateway owns RBAC),
  [ADR-0012](0012-federation-credential-model.md) (BFF federation credentials)

> ## Partly superseded — read this first
>
> **[ADR-0017](0017-provider-authority-is-delegated.md) replaces the parts of this ADR that let
> the provider assert authority over a tenant.** Authority is now *delegated by the tenant*, so
> §4, §5a, §6, §6a, §8 and §11a–§11d below are **history, not current design**. They were built,
> verified against real identity providers (Keycloak and Authentik), and replaced in design
> before they ever shipped in a release — the implementation was removed from `main` (#139)
> rather than announced, and no version ever offered it. See [ADR-0016](0016-reaching-many-tenant-gateways.md)
> (Rejected) for why the direction changed.
>
> **[ADR-0018](0018-device-credentials-by-reference.md) §6 supersedes §5b**, removing
> `provider:credentials` as a category: a credential held by reference is not the gateway's to
> disclose, so the tier it was a tier of no longer exists.
>
> **These sections still stand and are current design:**
>
> | | |
> |---|---|
> | **§1** | The tenant plane is single-tenant end to end |
> | **§2** | The provider plane is a separate population with its own IdP — ADR-0017 builds *on* this |
> | **§3** | The plane is immutable for the life of a session |
> | **§7** | Mass monitoring does not use the tenant API plane |
> | **§9** | A tenant sees every *human* provider act, with the actor pseudonymized |
> | **§10** | Offboarding: crypto-shred the content, tombstone the name — **referenced by ADR-0018 §4** |
>
> Kept rather than deleted, as [ADR-0014](0014-tenant-namespace-naming-and-network-isolation.md)
> and [ADR-0016](0016-reaching-many-tenant-gateways.md) are: the reasoning that produced a
> replaced decision is the part that stops it being re-proposed. ADR-0014 also *builds on* §7,
> §9 and §10, so this document remains load-bearing.

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

> **Superseded by [ADR-0017](0017-provider-authority-is-delegated.md).** The provider no longer
> holds cross-tenant power to exercise; the tenant delegates it.


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

> **Superseded by [ADR-0017](0017-provider-authority-is-delegated.md).**


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

> **Superseded by [ADR-0018](0018-device-credentials-by-reference.md) §6**, which removes
> `provider:credentials` as a category rather than re-scoping it.


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

> **Superseded by [ADR-0017](0017-provider-authority-is-delegated.md).** A tenant gateway no
> longer trusts a second issuer. The multi-issuer implementation is still in `main` and is
> being removed.


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

> **Superseded by [ADR-0017](0017-provider-authority-is-delegated.md)**, with §6.


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

The three questions this ADR was Proposed pending are settled in §8–§10 (2026-08-11), which
is what moved it to Accepted. **§11 is a fourth, and it did not exist at acceptance** — it
was surfaced by building §6a, when the provider scope ceiling turned out to block the very
grants §5 defines. It is recorded here rather than in the implementation notes because it is
a decision about the consent model, not a detail of how the multi-issuer code is written.

### 8. Grant lifetimes are absolute, and the elevated grants step up

> **Superseded by [ADR-0017](0017-provider-authority-is-delegated.md).**


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

### 11. An elevated grant reaches a tenant gateway as a verifiable claim on the token

§5 makes `provider:invoke` and `provider:credentials` **elevated**, time-boxed, individually
audited grants, and §5a/§5b require that they are not reachable from the everyday
`provider:admin`. The gateway enforces that by capping the provider issuer below `tools:call`
and `backup:*` — which means the ceiling that makes the carve-out real also blocks the grant,
and something has to lift it.

**Decision: the BFF obtains a grant claim (grant id + expiry + named tenant) and the gateway
verifies it, raising that issuer's ceiling for that request only.** Three alternatives were
considered.

**Rejected — a second provider issuer entry with a higher ceiling.** It moves the guarantee
out of this codebase's enforcement and into whatever a provider operator configured in an IdP
admin console. That is the opposite of the pattern held everywhere else here: the egress
policy is a guard function, not a policy note; the `MCP_SECRET_KEY` check is a fail-closed
startup assertion, not documentation; §8 describes grant lifetimes as machinery rather than a
policy file. It would turn the two highest-consequence grants in the system into exactly a
policy file, untestable by this project's own suite.

The decisive objection is narrower and harder: **it cannot express single-use at all.** A
`provider:credentials` grant is single-use by §8, and an issued bearer token is replayable
until expiry no matter which client minted it. Closing that needs a consumption record keyed
on something — so the "simpler" option requires the same machinery as the option it was meant
to avoid, precisely on the grant where the stakes are highest.

**Rejected as a competing option, retained as an overlay — a tenant-issued grant.** The
consent property is real and some contracts will require it. But requiring it universally
blocks an incident-response engineer on a customer being awake and reachable, which
correlates badly with the moments elevation is needed. More usefully, it is **not a different
mechanism**: it still mints a grant id with an expiry for the gateway to check, and differs
only in *who authorises the minting*. So the mechanism below is built once, and a future
per-tenant contractual flag can insert a tenant-approval step before the BFF requests the
claim — without changing a line of what the gateway validates. That is the same move §10
already made for retention and legal hold: a contractual question kept out of the
architecture.

**On the objection that this "teaches the gateway a provider concept" — that door is already
open, and was opened deliberately.** §6 has the tenant gateway trust a provider-specific
issuer; §6a has it maintain a per-issuer mapping *precisely* to stop tenant/provider
escalation; the implementation carries a `PLANE_PROVIDER` constant and a provider-specific
scope ceiling in code today. Refusing this increment to preserve a purity the gateway no
longer has would protect nothing. The line worth keeping is the *narrower* one §5 actually
draws: **the gateway never learns the provider scope vocabulary.** It learns that a verifiable
grant may raise an issuer's ceiling; `provider:invoke` and `provider:credentials` remain BFF
scopes and never appear in `ROLE_SCOPES`.

#### 11a. Three constraints that follow, named now rather than found in implementation

> **§11a–§11d are superseded by [ADR-0017](0017-provider-authority-is-delegated.md).** They are
> kept in full because they record what was actually measured against two real IdPs — including
> §11c's three-way split, which held up in live testing and may inform the replacement.


- **The grant claim must name exactly one tenant.** Single-use has to be consumed somewhere,
  and there is deliberately no shared state across tenant stacks (§1, [ADR-0004](0004-single-tenant-per-stack.md)).
  Consumption therefore lives in the receiving tenant's own Redis, which is only sound if the
  grant is bound to that tenant — an estate-wide grant would be independently spendable once
  per gateway. §8's *one tenant at a time* makes this natural rather than a new restriction.
- **Consumption fails closed.** If the consumption record cannot be written, the elevation is
  refused. The alternative is that a single-use credentials grant silently degrades to
  replayable-until-expiry exactly when the store is unhealthy, which inverts
  [ADR-0006](0006-fail-closed-distributed-defaults.md). For the same reason an elevated grant
  is refused outright in embedded mode, which has no shared store to consume against.
- **Do not overclaim what this moves in-house.** It makes *expiry* and *single-use*
  enforceable by the gateway. It does **not** make the justification enforceable — that a
  human gave a reason, and stepped up, remains an assertion by the provider IdP plus the
  BFF's audit record. The gain is real and bounded; stating it precisely is what keeps the
  §5a standard honest.

#### 11b. The provider IdP mints the claim (resolved 2026-08-14, **amended by §11c**)

> **§11c supersedes the "mints the grant" framing below.** Measurement against two real IdPs
> showed no product will mint this claim without custom code inside the issuance path. The
> constraints in *Three constraints, or Option A quietly becomes Option 1* all survive intact
> and are, if anything, load-bearing in more places. Read §11c for what is actually built.

**The provider IdP mints the grant claim itself, as part of a step-up flow.** One token, one
issuer, matching the verification model already built for §6. The alternative — the BFF as a
secondary claims issuer with its own signing key and JWKS endpoint — is rejected: it would
make the BFF audit writer, provider-credential holder *and* token issuer at once, and
[ADR-0012](0012-federation-credential-model.md) argues the general case against concentrating
those. The capability is standard across the IdP category in use, so keeping this open bought
nothing.

The claim-shaping logic is a **narrow, stateless component the platform team owns** — an
Action, a custom-claims provider, an authentication-tree node, depending on the product. It
runs inside the IdP's issuance path, so it is **not a signing authority** and inherits none
of Option B's key-management, rotation or JWKS-publication costs.

**Requirement note, written product-agnostically:**

1. Recognise a specific authentication context (`acr_values`) corresponding to the step-up
   event for elevated grants.
2. On issuance following that context being satisfied, inject a custom claim carrying the
   **grant id**, the **target tenant**, and an **expiry**.
3. Keep the component stateless — everything it needs arrives with the request.

##### Three constraints, or Option A quietly becomes Option 1

The reason Option B-as-a-second-issuer was rejected in §11 was that a security bound living
outside this codebase's enforcement is not a bound. That argument does not stop applying just
because the IdP mints the claim; it relocates. All three of these are gateway-side.

- **The grant lifetime is enforced by the gateway against its own clock, never read from the
  claim.** The BFF requests the grant, so if the hook echoes a requested `exp`, a compromised
  BFF mints itself a thirty-day `provider:credentials` grant and §8's *single-use* and
  *15 minutes* become suggestions. The claim's expiry may be **shorter** than the §8 ceiling
  for its grant type, never longer. This is testable here, which is the whole reason §11
  preferred a checked claim over a configured issuer.
- **Verify the authentication context in the issued token, not the fact that it was
  requested.** `acr_values` is a *request* parameter and an IdP may decline it and issue
  anyway. The gateway checks the resulting `acr`, and checks `auth_time` freshness so a
  session that stepped up hours ago does not satisfy a step-up now. Requesting is not
  achieving — the same shape as trusting a default because it is present.
- **Revocation is bounded by the window, not solved.** Terminating a provider admin's session
  does not invalidate a grant claim already inside an issued token. For
  `provider:credentials` the single-use consumption record (§11a) closes it after one use;
  for `provider:invoke` there is no revocation path inside its 15 minutes. Accepted as a
  residual, consistent with the existing "token replay within its TTL" position in
  `docs/threat-model-identity.md`, and named here so it is a decision rather than a gap.

#### 11c. The IdP asserts, the request selects, the gateway intersects (amended 2026-08-16)

§11b assumed the provider IdP would mint `mcp_grant = {id, tenant, scopes, exp}` given the
target tenant and grant class. Both halves were built against that assumption and verified
against a test double. **The assumption was wrong, and the double could not have caught it**:
it hardcoded the tenant and scopes, so it agreed with the code because both were written from
the same belief. The gap is at the protocol level, where no mutation of our own code reaches.
This is the same lesson as `MemoryGrantStore` in the notes below, one layer further out.

**What was measured (2026-08-16).** Full authorization-code + PKCE flows against two current
IdPs, decoding real tokens, with a genuine step-up flow and a real second factor:

- **The step-up request never carried the tenant or the grant class**, because the mechanisms
  for doing so are narrower than assumed. A custom authorization parameter never reaches a
  mapper. The OIDC Core §5.5 `claims` parameter is worse than useless here: on the product
  tested its mapper is id_token-only, string-only, and **echoes the client's own value back** —
  it asserts nothing. On the other product, claim mappings run at the **token** endpoint, by
  which time the authorization request no longer exists.
- **The requested `scope` is the only viable carrier.** It survives to issuance, it lands in
  both tokens, and an unregistered scope is refused at the authorization endpoint rather than
  dropped — the fail-closed behaviour this project requires everywhere else.
- **But a scope selects a tenant; it does not authorize one.** A user with no entitlement to a
  tenant requested that tenant's scope and received the claim. Making the IdP intersect
  *requested* against *permitted* requires scripting or dynamic-scope features that are
  preview or experimental — precisely the "configured in an IdP admin console" dependency §11
  rejected, now with the added cost of running unsupported features.

**Decision: split the claim by who can be trusted to say it, and intersect in the gateway.**

| Who says it | Claims | Why it can be trusted |
|---|---|---|
| The IdP asserts | `acr`, `auth_time`, `mcp_allowed_tenants` | Derived from the authentication event and the directory. The client cannot influence any of them. |
| The request selects | `mcp_grant.tenant`, and the grant class | Chosen by the BFF, therefore **not** trusted on its own. |
| The gateway intersects | `mcp_grant.tenant ∈ mcp_allowed_tenants` | The security bound, enforced in this codebase against a claim the client cannot forge. |

`mcp_allowed_tenants` is a directory attribute on the provider operator — the estate they may
act on at all. It is not a grant and confers nothing by itself; §8's act-on-tenant window,
the justification, the single-use consumption record and the absolute lifetime all still
apply on top of it.

**The intersection belongs to the gateway, not the BFF.** The BFF chooses the scope, so a
compromised BFF asking for a tenant its operator may not touch is exactly the case this must
catch — a check in the BFF would be the attacker validating their own request. Both claims
arrive in the **access token** the gateway already receives as a bearer, so it can perform the
intersection unaided, with no new call and no new trust relationship. This keeps §11's
central property: the bound lives in code this project's suite can test.

**This is a smaller claim than §11b made, and a more honest one.** The IdP is no longer
described as minting a grant; it attests to an authentication event and an entitlement, which
is what an IdP is actually authoritative for. Everything that makes the result a *grant* —
scope mapping, lifetime, single use, audit — was already gateway-side and stays there.

##### Consequences for the three constraints

- **Lifetime is unchanged and now unavoidable.** The claim carries no expiry at all, so there
  is nothing to echo. The gateway computes the deadline from `auth_time` against its own clock
  and caps it at the §8 ceiling for the grant class.
- **Verifying `acr` is now the *only* freshness protection, and must be treated as such.**
  A client-supplied `max_age=0` was measured to be **inert** once the IdP binds a step-up flow
  with its own re-authentication age: the flow's configuration wins and no re-prompt occurs.
  Sending `max_age=0` is still correct and stays, but it is a request, not a guarantee — the
  guarantee is the issued `acr` plus `auth_time` freshness. The IdP-side configuration that
  actually forces a fresh step-up is a deployment requirement, documented with the runbook,
  not something the gateway can compel.
- **Revocation is unchanged** — bounded by the window, closed after one use for
  `provider:credentials`.

##### Revised requirement note, product-agnostically

1. Recognise a step-up authentication context and **enforce** it, emitting the achieved
   context as `acr` in the access token. A product that accepts `acr_values` and issues
   without enforcing it is not usable as the provider IdP.
2. Emit `auth_time` in the access token.
3. Emit the operator's tenant entitlement as a claim derived from the directory, not from the
   request.
4. Allow the request to select a tenant and grant class through requested scopes, and **refuse
   an unrecognised scope** rather than dropping it.
5. ~~Emit a token identifier unique per issuance, to key the single-use consumption record.~~
   **Withdrawn 2026-08-16 — see §11d.** No measured product satisfies it, and requiring it
   was the gateway asking the IdP to solve a problem the gateway had misframed.
6. Set an audience the gateway can check — the default audience is typically not the gateway.

Point 1 is the discriminating requirement: of the two products measured, only one satisfies it.

#### 11d. Single use is consumed against the elevation, not the grant id (2026-08-16)

**Found by attaching a real IdP, not by any test.** Every grant claim in the suite was
hand-built and every one carried a distinct `id`. Keycloak's only stock way to emit
`mcp_grant.id` is a hardcoded claim mapper, which emits a **constant**. Measured end to end
with two legitimate elevations, each behind its own fresh TOTP step-up: `backup:read`
returned 200, then 401 *"already been spent"*. The credentials class worked exactly once per
deployment, ever — and requirement 5 above was the gateway insisting the IdP fix it.

The mechanism was not too strict. It was enforcing a **different property** from the one §8
states. §8 reads *one operation, re-entry by step-up*, so what consumption must identify is
the elevation: **subject + grant id + `auth_time`**, hashed. Three choices inside that, each
the opposite of the obvious one:

- **`auth_time`, not `jti`.** The token id is the intuitive key and it is unsound: a refresh
  mints a new `jti` from the *same* authentication event, with the same `acr` and the same
  grant claim, so a jti-keyed record grants one spend per refresh — single use defeated from
  inside the window it exists to hold across. `auth_time` is the only value that changes
  exactly when a new step-up happens, and it is strictly the stronger key, since two tokens
  sharing a `jti` necessarily share an `auth_time`.
- **The subject is in the key and takes nothing away.** With a per-issuance id it is
  redundant; with a constant one it stops the first operator to run a backup from locking out
  every colleague. It weakens no replay defence — a replayed token carries its victim's
  subject and collides with the victim's own record. The subject is already issuer-qualified
  (`oidc:<iss>#<sub>`), which is what keeps two trusted issuers apart.
- **`auth_time` is normalised to whole seconds**, so `1700000000` and `1700000000.0` are one
  elevation. Rounding can only merge neighbouring events, never split one — the closed
  direction.

`shared/keys.py` used to argue *"keyed on the grant id and nothing coarser; keyed on the
subject instead, a support engineer's second grant of the day is refused as a replay"*. The
reasoning was right and the conclusion did not follow: the finer key refused their second
grant **ever**. A composite containing the subject is not the coarsening that warning meant.

##### Implementation (2026-08-16)

`entitlement_claim` joins `step_up_acr` and `grant_claim` as per-issuer configuration,
defaulting to `mcp_allowed_tenants`. `verify_grant` performs the intersection.

Three details are load-bearing and none is obvious from the outside:

- **It sits after the tenant is validated and before consumption.** After, because there is
  no point asking whether an operator is entitled to a tenant the grant does not correctly
  name. Before, because otherwise an operator entitled to nothing could present someone
  else's single-use credentials grant, have it refused, and *still* burn the id — disarming
  a legitimate grant permanently from an account with no authority at all.
- **A missing or malformed entitlement claim refuses.** "No entitlement stated" and
  "entitled to everything" must never be the same thing: were they, an IdP that simply does
  not emit the claim would silently restore the pre-§11c behaviour with no error anywhere.
- **One membership test carries the property.** Mutation testing showed the emptiness and
  type-filtering branches were removable without changing a single outcome — an empty list,
  a blank string and a list of non-strings all fail the membership test anyway. They were
  defence in depth in appearance only, so they now shape the *message* (a missing IdP
  mapping and an unentitled operator are different problems) rather than standing as
  separate guards that no test could distinguish.

## Implementation notes — gateway-side multi-issuer (2026-08-14)

§6/§6a are built in the gateway: `gateway.oidc.issuers` takes a list, each entry carrying
its own `audience`, `group_roles`, JWKS cache and `plane`. The legacy single-issuer form
still works untouched and lands on the tenant plane, because a security change that forces
every existing operator through a config migration gets deferred, and then nobody gets the
isolation.

**The trap this cost the most thought to avoid.** The obvious way to accept two issuers is
`jwt.decode(..., issuer=[a, b])` over a merged key set. That accepts a token signed by
issuer **A**'s key while claiming `iss: B` — PyJWT is behaving correctly, since `iss` is in
the accepted list and the key it was handed verified the signature. The *composition* is
what is wrong, and it is a complete impersonation primitive: a tenant IdP operator mints
themselves provider identity on their own gateway. So the issuer is resolved first, from
the unverified claims, and used only to select a validator; every subsequent check comes
from that one issuer's config. Reading `iss` before verification is safe precisely because
it selects a verifier and never grants anything.

`plane` binds issuer identity → eligible scope set as §6a requires. The provider ceiling is
`devices:read` + `devices:write` + `metrics:read` — §5a's carve-out, with `tools:call` and
every `backup:*` scope excluded. A provider-plane group mapped to a role that exceeds it is
refused **at startup**, and the ceiling is applied **again at validation**, because config
can be reloaded and `ROLE_SCOPES` can gain a scope after the startup guard has run.

The OIDC principal subject is now `oidc:{issuer}#{sub}`. `sub` is unique within an issuer,
not globally: `admin` at the tenant IdP and `admin` at the provider IdP are two different
humans, and collapsing them puts both on one line of the tenant's hash-chained audit with
no symptom, because both requests succeed. **This changes the audit subject format for
existing single-issuer deployments** — see the changelog.

## Implementation notes — gateway-side elevated grants (2026-08-14)

§11 is built in the gateway: `device_mcp_gateway/grants.py` holds the claim, the policy
table and `verify_grant`; `OIDCValidator._apply_grant` is where a verified grant raises the
issuer's ceiling for one request. The claim as implemented:

```json
"mcp_grant": {
  "id": "g-7f2",              // required; what consumption and audit key on
  "tenant": "acme",           // required; a STRING, must equal gateway.tenant_id
  "scopes": ["tools:call"],   // required; closed range, gateway scopes only
  "exp": 1755200000           // optional; may only SHORTEN the window
}
```

The claim **name** is per-issuer config (`grant_claim`, default `mcp_grant`), because an
IdP's custom-claims hook is often constrained to a namespaced name like
`https://mcp.example/grant`.

**How §8's two grant classes reach a gateway that must not learn the provider vocabulary.**
The policy table is keyed on *gateway* scopes: `tools:call` is the `provider:invoke` class
(900s absolute window, replayable **within** the window, since §8's grant gates initiation
rather than completion and one debugging session is several calls); `backup:read`,
`backup:write` and `backup:export-portable` are the `provider:credentials` class (single
use). §11's line therefore holds — the string `provider:invoke` appears nowhere in the
gateway.

**The grantable set is `ALL_SCOPES − <provider ceiling>`, asserted by a test** rather than
left as a comment: the two are defined in different modules, and a new scope added without
deciding which side of §5a it falls on would otherwise pass unnoticed.

**Single-use grants still get a window (300s)**, though §8 gives that class none — otherwise
a grant minted last year is spendable today. It is deliberately no *looser* than the invoke
window, and a test pins that relationship rather than the durations, which are configuration.

**A mixed grant takes the strictest policy** — single-use if any scope is, and the shortest
window. The alternative is that adding `tools:call` to a credentials grant *relaxes* it.

**The deadline is anchored on `auth_time`**, not `iat` and not "now". The window runs from
the step-up, which is what makes it absolute (§8) — and it makes one mechanism serve both
§11b constraint 1 (lifetime from our clock) and the `auth_time` freshness half of constraint
2: a 15-minute window *is* a 15-minute step-up freshness requirement.

**`leeway` is clock-skew tolerance, not slack.** `auth_time` and any claim `exp` are stamped
by the IdP's clock, so the same tolerance already applied to the token's own `exp` applies
here. It is bounded and configurable; `leeway: 0` gives none.

**An invalid grant refuses the whole token**, rather than quietly serving the unelevated
principal. A caller presenting a grant is asking to act elevated; the fall-back surfaces as
a 403 on some later route, which reads as a permissions bug — and an expired credentials
grant would be indistinguishable from a typo in a role mapping.

**A grant on a ceiling-less (tenant-plane) issuer is ignored, not honoured, and the plane is
consulted *before* the union.** Do the union first and a tenant `viewer` whose own IdP can
be made to emit the claim gains `tools:call` on their own stack — §6a's escalation one layer
up.

**A grant cannot rescue an unmapped group.** It lifts a ceiling; it is not an alternative
route to authority. A subject whose groups map to nothing stays at zero scopes.

**Consumption is last**, after every other check, so a grant refused for clock skew or a
wrong `acr` does not burn its id and strand a legitimate single-use grant. Consumption is
`SET key NX EX ttl` in the receiving tenant's own Redis (§11a) — atomic claim-or-fail in one
command, so two concurrent replays cannot both win — and any error propagates as a refusal.
The key identifies the **elevation**, not the claim's `id` (§11d): a stock IdP mapper emits a
constant id, and keying on it made the credentials class spendable once per deployment.

**Embedded mode refuses every elevated grant**, not only the single-use ones (§11a). This
falls out of the wiring rather than being a separate check: the store is attached only in
the distributed branch of the lifespan.

**Audit.** A request acting under a grant carries `grant=<id>` on its audit records. The
field is emitted **only when present**, so records for unelevated requests keep the exact
field set earlier releases wrote and existing hash chains verify across the upgrade. It is
attached at `audit_request` (which every `backup:*` route goes through) *and* at each
transport's tool-dispatch record, because the invoke class does not pass through
`audit_request` — and it is the class §8 makes replayable inside its window, so one grant id
legitimately spans several records and is the join key for reconstructing the session.

**New config.** `gateway.tenant_id` is deployment-level: one gateway serves one tenant
(§1, [ADR-0004](0004-single-tenant-per-stack.md)), so it is read once and handed to every
issuer entry rather than repeated per entry. `step_up_acr` and `grant_claim` are per-issuer.
A provider-plane issuer with no `gateway.tenant_id` is **refused at startup** — a gateway
that does not know its own name can never honour a grant, and discovering that during an
incident is the worst possible moment. Tenant-plane issuers are unaffected, so no existing
single-issuer deployment is forced through a config change.

**Testing.** `tests/test_elevated_grants.py` was written before the implementation and is
the deliverable as much as the code: §11 preferred a checked claim over a configured issuer
*because* a bound in an admin console is untestable here, and that argument only pays if the
checks exist. The claims are synthetic and signed by the test rig, which is the right way to
test §11b constraint 2 — a real IdP that always complies with `acr_values` cannot exercise
the declined-step-up path. Wiring a real provider IdP is live-cluster verification, later.
