# ADR-0012: Credential model for BFF provider federation

- **Status:** Proposed
- **Date:** 2026-08-11
- **Related findings:** F-30 (end-to-end identity propagation), F-57 (hash-chained audit)
- **Builds on:** [ADR-0004](0004-single-tenant-per-stack.md) (one stack per tenant),
  [ADR-0007](0007-federated-identity-oidc-and-gateway-rbac.md) (per-user OIDC, gateway owns RBAC)

## Context

[ADR-0004](0004-single-tenant-per-stack.md) makes tenancy a deployment boundary: each
tenant gets its own stack, Redis, `MCP_SECRET_KEY`, and keys. That decision holds. What it
leaves open is the operator experience — someone running several tenant stacks has several
UIs and no aggregate view. The proposal is a **providers UI**: one BFF that registers N
gateways as *providers* and fans out reads across them, unifying the view without
co-hosting anything. The isolation boundary is untouched; only the console is shared.

The credential question is how that BFF authenticates to each provider, and **the honest
starting point is that this is not a greenfield decision.**

`upstream_bearer()` in the UI repo's `bff/app/security.py`
already resolves an OIDC session to **the user's own access token**, and `relay.py`
presents it on every proxied call; only a legacy password session falls back to the
configured admin token. So F-30 — real per-user identity reaching the gateway, real
subjects in the gateway's hash-chained audit — is **built and shipped today**, not
aspirational. ADR-0007 still says `Proposed`; the per-user relay half of it is in
production.

That reframes the obvious federation design. "One service token per provider, held by the
BFF" is not a small new risk to note in the threat model — it is a **regression** that
would re-introduce the confused deputy ADR-0007 was written to remove, silently downgrading
every provider's audit trail from the acting human back to a shared machine identity.

The second fact is worse in combination. **The BFF has no audit logging at all.** A search
of `bff/app/` returns exactly one logging-adjacent line: a `501` stub in
`bff/app/routers/api.py` telling the
operator to point their own Loki at it. Today that is survivable precisely *because* the
per-user relay means the gateway's own chained audit records the real principal. Federation
inverts this: cross-provider actions originate at the BFF, and if the BFF forwards a
service token and keeps no log, an action against a tenant becomes attributable to nobody.
The two gaps are only tolerable while they don't overlap.

The real obstacle to per-user tokens everywhere is narrower than "the gateway lacks a tenant
concept" — each gateway already validates user tokens against its own configured `issuer`
and `audience`, and needs no tenancy model to do it. The obstacle is **identity federation
across N independently-configured IdPs**: provider A trusts Entra, provider B trusts an
on-prem Keycloak, and one user's token from A's issuer is correctly rejected by B. Nothing
in the gateway fixes that; it is resolved (or not) in the operator's IdP topology.

## Decision (proposed)

**1. BFF-side audit logging is a prerequisite for federation, not a parallel workstream.**
Hash-chained on the F-57 model the gateway already uses, bound to the authenticated
principal, covering every provider-directed action. Federation does not ship before it.

**2. Per-user token relay is preserved wherever the IdP topology allows it, and that is the
design goal — not a cost to be traded away.** Concretely:

- **Shared issuer across providers** (one IdP, each gateway a distinct audience, or a shared
  audience): relay the user's token unchanged. This is today's behaviour and needs no new
  mechanism.
- **Distinct issuers, token exchange available** (RFC 8693): the BFF exchanges the user's
  token for one the target provider's issuer will accept. Preferred over any service
  credential.
- **Distinct issuers, no exchange:** fall back to a signed BFF identity assertion carrying
  the real user — the mechanism ADR-0007 §4 already names as its fallback.

**3. A per-provider service token is the last resort, and it is a documented degradation.**
Where it is unavoidable, the affected provider is **marked as such in the UI**, and the BFF
audit record carries the real principal even though the gateway's cannot. An operator must
be able to see which providers have lost per-user attribution, rather than discovering it
during an investigation.

**4. Provider credentials are stored encrypted, under the BFF's own key, and are covered by
the BFF's own backup story** — separate from [ADR-0011](0011-backup-and-restore.md), which
deliberately scopes itself to one gateway's Redis.

## Consequences

- **Positive:** federation cannot silently undo F-30; the strongest available attribution is
  used per provider rather than the weakest being applied uniformly; the BFF gains audit it
  should have had regardless; the degraded case is visible instead of implicit.
- **Negative / cost:**
  - Three credential paths to build and test instead of one, and the fallbacks are the
    fiddly ones.
  - BFF audit is real work ahead of the feature that motivated it, and it delays the
    providers UI.
  - The BFF becomes a store of provider credentials — a new high-value target, on the other
    side of a trust boundary from the gateway, needing its own encryption, rotation, and
    backup.
  - Where token exchange is unavailable and assertions are not configured, a provider still
    lands on a service token. This ADR makes that visible and audited; it does not remove it.
- **Follow-ups:**
  - Threat-model addendum for the BFF → N-providers boundary, extending
    [threat-model-identity.md](../threat-model-identity.md).
  - ADR-0007 should move to `Accepted` (or be superseded) — it describes as proposed a
    per-user relay that is shipped.
  - [multitenancy.md](../multitenancy.md) needs revision once this lands: it currently
    presents single-tenant-per-stack with no aggregate-console story.

## Scope after the 2026-08-21 review

Checked against the code and against [ADR-0017](0017-provider-authority-is-delegated.md).
This ADR stays **Proposed**, but for a sharper reason than "unbuilt": **three of its four
Decision items have been overtaken by ADR-0017, and no record noticed** — 0017 and 0020 both
cite this one approvingly, and nothing supersedes it, which is how the drift went unseen.

**Item 1 (BFF audit is a prerequisite for federation) stands, unchanged.** Chaining,
pseudonymization-at-write, per-tenant-key encryption and attribution are all verified strong
in `bff/app/audit.py`. Coverage is the known gap: `_audited()` audits mutations only, and
deliberately — with per-user relay the gateway's own chain already records the human behind
every read.

**Item 3 (per-provider service token as a documented last resort) has no remaining
occasion.** It was reserved for exactly one case: *distinct issuers, no token exchange
available.* [ADR-0017](0017-provider-authority-is-delegated.md) §7's Tier 0 was constructed as
a floor precisely to need nothing shared between the two identity systems — no common issuer,
no exchange, and no tenant-side IdP at all (the Lite/local-auth deployment still clears it).
There is no gap left between what item 3 was for and what Tier 0 already covers. **The
visibility principle underneath it survives and should be carried forward**: an operator must
see when attribution has degraded, rather than discovering it during an investigation.

**Item 4 (provider credentials encrypted at rest under the BFF's own key) follows item 3.**
It is the storage requirement for item 3's fallback token; with nothing left to justify the
token, there is nothing left to store. It also contradicts §7 directly — a Tier 0 credential
is gateway-minted, short-lived, scoped to one grant, and *"returned only to the session that
raised it"*. There is no standing per-provider credential for a store to hold.

**Item 2's scope needs re-examination — it is not simply untouched.** Its three-tier
hierarchy (same-issuer relay → token exchange → signed BFF assertion) exists to carry a
provider operator's identity through a BFF and into N different tenant gateways.
[ADR-0017](0017-provider-authority-is-delegated.md) §6 says that transit does not happen:
*"the provider console holds no credential for a tenant's data plane at all"* — an operator
needing a tenant's data plane enters **that tenant's own console** with the delegated
credential. Tracing what still crosses the boundary leaves:

| Provider-side function | Credential into a tenant stack? |
|---|---|
| Estate-wide observability (§5) | **No, by construction** — and §5 forbids building such a view by querying N tenant APIs with a credential |
| The catalog ([ADR-0020](0020-the-device-catalog.md)) | **No** — the provider's own store; tenants claim *from* it |
| Estate / tenant list | **No** — navigation, never authorization |
| Raising a pending support request (§7) | **The one remaining provider → tenant write**, and it carries no authority — it asks for permission. 17.3 already fixed its shape: provider-side polling, scoped to the originating identity |

So what survives of item 2 is (a) the ordinary single-gateway tenant relay — which was never
a federation mechanism and is separately verified against
[threat-model-identity.md](../threat-model-identity.md)'s gate — and (b) whatever
authenticates that one request channel. Both are much narrower than the hierarchy was built
for. Whether this ADR is then *largely superseded by ADR-0017*, retaining item 1 and the
ordinary-relay case, is the open status question; the pending-request channel is the loose
thread that decides it.

**Sequencing follows from that, and it is a dependency, not a date.** The remaining
follow-ups — the BFF → N-providers threat-model addendum, per-provider degradation
visibility, the aggregate-console revision of [multitenancy.md](../multitenancy.md) — all
wait on [ADR-0021](0021-separate-console-applications.md)'s provider console, build-order item
8. Writing the threat-model addendum first would model a boundary whose shape is not settled;
that addendum declares itself *gating, required before implementation*, and the discipline
only pays if the thing being modelled is the thing that gets built.

**One correction to make when item 1's coverage gap is closed.** `_audited()`'s docstring says
read auditing changes "when provider federation lands", which is imprecise in the direction
that costs work: under federation with per-user relay *working*, the gateway still sees the
person, so re-auditing reads duplicates what the design deliberately avoids. The trigger is
narrower — a provider whose attribution has actually degraded.

## Alternatives considered

- **One service token per provider, held by the BFF** (the original sketch): rejected as the
  default. It is a regression from shipped behaviour, not a new trade-off, and it re-creates
  the confused deputy in exactly the place ADR-0007 removed it.
- **Per-user tokens only, no fallback:** rejected — it makes federation impossible for the
  common enterprise case of independently-configured IdPs, which is the case most likely to
  want an aggregate console in the first place.
- **Push federation into the gateway** (one gateway fronting the others): rejected — it
  makes the aggregation point a shared component across tenants, which is precisely what
  [ADR-0004](0004-single-tenant-per-stack.md) rules out. Aggregation belongs in the console.
- **Ship federation now, add BFF audit after:** rejected on review. The two gaps are only
  individually tolerable; shipping in that order creates a window where cross-tenant actions
  are attributable to no one, and windows like that are rarely closed on schedule.
