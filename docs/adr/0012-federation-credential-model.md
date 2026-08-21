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

Checked against the code and against [ADR-0017](0017-provider-authority-is-delegated.md) §7.
The result narrows this ADR rather than superseding it, and it stays **Proposed** for a
documented reason rather than a vague one.

**Decision item 2 (per-user relay preserved, with the same-issuer → token-exchange →
BFF-assertion fallback hierarchy) is validated and hardened, not superseded.** ADR-0017 §7,
the fix behind its open question 17.2 — the provider-plane relay gets its own call path with
*no fallback credential configured at all*, so a missing operator bearer fails outright
instead of silently succeeding as the shared admin token — and PR #127 kept as a permanent
regression test together make this ADR's "per-user relay is shipped" claim **structurally
true rather than true-by-observation**. Not re-opened below.

**Everything still open is one sequence, not five independent items.**

| # | Item | State |
|---|---|---|
| 12.4 | Threat-model addendum for **BFF → N providers** | **First.** [threat-model-identity.md](../threat-model-identity.md) covers IdP → BFF → *one* gateway; its I4 boundary is singular. That document states its own convention — *gating, required before implementation* — which is the discipline that gated ADR-0007's auth core, so this is written **before** the registry, not after |
| 12.2 / 12.3 | Per-provider degradation visibility; provider credentials under the BFF's own key | **One blocker, not two.** Both wait on the **provider registry**, which does not exist: `bff/app/config.py` still declares `gateway_url: str`, singular — the exact single-target shape this ADR's own Context describes. There is nothing for a per-provider flag or a per-provider credential to attach to. The BFF's only encryption today is `audit_content_key`, which encrypts audit *record content* per tenant (ADR-0013 §10) — a different concern |
| 12.1 | BFF audit coverage | **After 12.2**, because its fix depends on 12.2's flag. Chaining, pseudonymization-at-write, per-tenant-key encryption and attribution are all verified strong; **coverage is the gap**. `_audited()` audits mutations only, deliberately — with per-user relay the gateway's own chain already records the human behind every read |
| 12.5 | `multitenancy.md` aggregate-console revision | **Last — after the registry ships, describing what was built.** Writing it now would put the docs *ahead* of reality, the inverse of the stale-status defects found repeatedly in this repository and worse for an operator-facing document, because a reader cannot distinguish speculative documentation from accurate documentation by looking at it |

**One correction to `_audited()`'s own docstring, to make when 12.1 is built.** It says read
auditing changes "when provider federation lands", which is imprecise in the direction that
costs work: under federation with per-user relay *working*, the gateway still sees the person
and re-auditing reads would duplicate exactly what the current design avoids. The real trigger
is narrower — **any provider in item 3's service-token-degraded state**, where attribution is
lost at both ends at once. So the fix is a conditional keyed on that provider's `degraded`
flag, not a blanket policy change.

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
