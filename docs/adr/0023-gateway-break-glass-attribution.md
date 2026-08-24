# ADR-0023: Gateway break-glass is individually attributable, expiring, and loud

- **Status:** Accepted
- **Date:** 2026-08-20
- **Related:** [ADR-0007](0007-federated-identity-oidc-and-gateway-rbac.md) (original static-key mechanism),
  [ADR-0017 §4](0017-provider-authority-is-delegated.md) (break-glass's four required
  properties, named but explicitly not designed there), [rbac-roles.md](../rbac-roles.md),
  [ADR-0018](0018-device-credentials-by-reference.md) (the `secret://` resolver reused below)

## Context

ADR-0017 §4 states four properties break-glass access must have to remain a last resort rather
than a convenience: credentials generated at deploy time and held in a secret store, never in
configuration; use that emits a high-severity audit event and a tenant notification, not an
ordinary log line; rate-limiting and expiry, so it cannot become a standing operating mode; and
scope limited to the tenant's own admin scopes, with no separate larger capability. §4 names
these as requirements and explicitly defers designing the hardening itself.

The gateway's actual break-glass mechanism today — `MCP_ADMIN_KEY`, ADR-0007 — was designed
before §4 existed and does not meet three of its four properties:

- **Fails.** It is describable via `gateway.rbac` config entries, not held exclusively in a
  secret store — the opposite of "never in configuration."
- **Fails, as far as documented.** Nothing distinguishes its use from ordinary static-key
  authentication in the audit trail. No high-severity event, no tenant notification.
- **Fails.** A static key has no lifetime and no call budget. Nothing prevents it from becoming
  the operating mode §4 says it must not become.
- **Met.** It grants only the local gateway's own `admin` scopes — no separate provider
  capability.

The deeper problem underneath all three failures is the same one: `MCP_ADMIN_KEY` is a single
shared bearer value. Every holder authenticates identically. There is no way to know, from the
credential alone, which specific person used it — which is also what blocks meeting property 1
and property 2 correctly, since "generated per person, held per person" and "attributable in the
audit" are the same underlying requirement viewed from two angles.

## Decision

Break-glass access moves from one shared key to **one individually-generated, individually-held
credential per authorized person**, using the `gateway.rbac: [{name, key, role}]` list mechanism
that already exists — not a new schema — with one addition: a `break_glass: true` flag per
entry.

**Why the flag, and why it must be selective.** `gateway.rbac` already serves ordinary,
legitimate static-key use cases — CI, test fixtures, persistent machine credentials — that
should not become loud, flagged, or expiring; doing that indiscriminately would make routine
automation noisy for no security benefit. The flag scopes §4's stronger treatment to exactly the
entries that are actually break-glass, leaving every other static-key use case as it is today.

**What the flag changes, mapped directly to §4's four properties:**

1. **Generation and custody.** A flagged entry's key is generated at deploy or provisioning
   time — never operator-chosen — and delivered out-of-band **to that one named individual
   specifically**, not to a shared team channel or a group-readable secret. This is the part
   easy to get only half right: recording a name in the audit is not the same as the credential
   actually being held by one person. If every named key lives in one shared team vault that
   the whole platform team can read, the audit will record "Alice" when it was actually Bob
   using Alice's key from the shared store — attributable in form, wrong in fact. Custody has to
   be as exclusive as the name implies, or the property isn't actually met.

   **This must be verified, not documented.** A checklist line asking someone to "deliver this
   individually" is a reminder, not a guarantee, and it is exactly the kind of step that gets
   shortcut under deploy-day pressure — the same "must be remembered per call site" shape this
   project has structurally avoided everywhere else it had the choice (the `MCP_SECRET_KEY`
   startup requirement, the restore digest preflight, the elevated-token route-eligibility
   marking). Where a `break_glass: true` credential is delivered as an individual Kubernetes
   Secret — the natural fit given this project's existing deployment model — custody is a real,
   queryable property: every Secret labeled `break_glass: true` should have exactly one subject
   with read access via its RoleBindings, checked automatically as a deployment-pipeline step,
   not trusted to a runbook line. **This check rides the same 90-day reissuance cycle from
   property 3** rather than existing as a separate thing anyone has to remember to re-run —
   every reissuance re-verifies custody as the same event, not two mechanisms that can drift
   out of sync with each other over time. Where full automation genuinely isn't possible (a
   password manager without API-level ACL inspection, say), the fallback is a manual,
   explicitly required, signed-off gate in the deployment runbook — a real gate someone
   affirmatively completes and records, not a passive reminder — treated as the fallback, not
   the default.

   **The credential itself is a `secret://` reference through ADR-0018's resolver, not a literal
   value in the config document.** `gateway.rbac[].key` as originally specified read the key
   straight out of `gateway.rbac` in the config file — the declared schema carries `api_key: str`
   and `rbac: list`, literals, not references. That directly fails "never in configuration"
   regardless of how the value inside it was generated or delivered: the *document* still carries
   the actual credential. `break_glass: true` entries resolve their `key` through the same
   resolver ADR-0018 built for device credentials, rather than reading a literal — the mechanism
   already exists, this is not new machinery.
2. **Audit and notification.** Using a `break_glass: true` credential emits a dedicated
   high-severity audit event, distinct from ordinary static-key authentication, and fires a
   dedicated Prometheus alert (`MCPBreakGlassActivated`, `severity: page`, deliberately with
   no `for:` delay — every SLO and operational alert in that file waits 2–15 minutes to filter
   transients, and an activation is not a transient; the requirement is loud, not
   eventually-consistent) — not folded into routine request logging where it would read as
   unremarkable. This is the metrics plane, not the console-level break-glass path in the UI
   spec — that path is unbuilt, and citing it here would be a false claim of coverage. The
   metrics plane is the correct delivery mechanism regardless: per ADR-0017 §5, it's *"the
   only thing a provider sees without a tenant's involvement, so it must be good enough to run
   an estate from"* — break-glass activation is exactly the kind of signal that requirement was
   written for.

   **The audit subject must be the configured name, and a flagged entry without one must refuse
   to load — never fall back to the role name.** A `break_glass: true` entry with no `name` set
   must not silently audit as `key:<role>`; every such entry would then be indistinguishable
   from every other, which is precisely the shared-anonymous-credential problem this ADR exists
   to close, reappearing through an omitted field instead of a shared key. `name` is mandatory,
   validated at config-load time, for any entry carrying the flag.
3. **Expiry, and flagging where §4 said rate-limiting.** A flagged credential carries a real
   lifetime, not indefinite validity — starting default **90 days**, matching a widely-used
   compliance rotation cadence, with the same escalating-warning mechanism built for standing
   consent (§3, ADR-0017) rather than a silent cutoff: prominent notice at two weeks and again
   at three days before expiry.
   The case for a warning here is if anything stronger than it was there — a break-glass
   credential that silently expires is discovered dead exactly when someone needs emergency
   access during a real IdP outage, the worst possible moment to find out.

   **This is a deliberate departure from §4's literal wording, and it should be read as one.**
   §4 asks for a credential that is "rate-limited and expiring". This ADR delivers the expiry
   and **declines the rate limit**, substituting a review flag — so nothing in this mechanism
   is rate-limited, and a reader expecting a limiter will not find one.

   The reason is that a call budget is actively the wrong shape here, not merely unnecessary: a
   fixed low call limit could cut off a legitimate incident response mid-session, the exact
   failure mode a mechanism meant to work when everything else is broken cannot afford.
   Instead: **no throttling within an active session** — a real incident may need many calls
   over hours, and artificially limiting that defeats the purpose at the moment it matters most.
   **Flag, don't hard-block, on cross-session reactivation frequency** — the actual signal worth
   watching isn't call volume, it's how often the credential gets activated *at all*. One
   activation during a genuine outage is fine regardless of call count within it; the same
   credential reactivating repeatedly across separate weeks is the real tell that it's being
   used as routine access rather than emergency access, and that should raise a loud review
   flag, not silently lock someone out during what could be a second genuine emergency.

   All of the above are starting defaults, not final values — instrument from day one
   (issuance timestamps, the per-use audit event from property 2, time-since-last-use per
   credential) so the real expiry window and reactivation threshold come from observed usage,
   the same treatment already given to cache TTL and plan-digest validity elsewhere in this
   ADR set.
4. **Scope.** Unchanged — still only the local gateway's own `admin` scopes, same as today.

**Revocation becomes per-person, which is the practical payoff, not just an audit nicety.** A
shared key means one person's departure or one person's compromised laptop forces rotating
everyone's access. A named credential means revoking exactly the one person's entry, with zero
effect on anyone else's ability to use break-glass when it's next needed.

**`MCP_GATEWAY_API_KEY`/`gateway.api_key` is in scope too, but conditionally — on whether it's
actually functioning as break-glass, not on which config field it happens to be.** Per
`build_authenticator`'s own docstring: *"Static API keys are always built (break-glass /
bootstrap). If `gateway.oidc` is enabled, the result is a `CompositeAuthenticator` (OIDC JWT →
else static key → else 401); otherwise the plain `Authenticator` is returned unchanged so
existing single-key / no-key deployments behave exactly as before."* That "otherwise" is the
dividing line:

- **OIDC configured** — the static key is a genuine fallback, tried only when the JWT path
  fails or is absent. This is break-glass in substance, not just in a comment calling it that,
  and it must get the identical `break_glass: true` treatment as `MCP_ADMIN_KEY`: a named
  entry, a `secret://` reference, reactivation flagging, expiry, loud audit. Leaving it as an
  unflagged, unhardened parallel path here means property 1 is not met for the system as a whole, no
  matter how well `MCP_ADMIN_KEY` itself is hardened.
- **No OIDC configured at all** — there is no fallback happening, because there is nothing to
  fall back *from*. The plain `Authenticator` is the only one built, and this key is the
  deployment's ordinary, continuous, everyday credential — not a rare emergency path. Applying
  break-glass treatment here would be wrong, not merely unnecessary: flagging "reactivation
  frequency" on what is, for this deployment shape, normal and expected traffic would either need
  a threshold so generous it means nothing, or would flag correct everyday operation as an
  incident on every quiet-gap boundary. This case is deliberately left untouched, exactly as it
  works today.

**One carve-out this makes necessary, and it is not hypothetical.** In an OIDC-configured
deployment the BFF's *password* sessions already relay this key on every request — `upstream_bearer`
returns `None` for a password session precisely so the client falls back to its configured admin
token. That is continuous, ordinary traffic on the credential the rule above would flag: it would
emit a high-severity audit record on **every request**, page on the first request after each quiet
gap — so roughly daily, whenever traffic pauses longer than the session gap — and permanently trip
the reactivation-frequency review flag, since ordinary daily use crosses any threshold meant to
catch emergencies. The 90-day expiry would then take the password path down entirely. The flag is
selective by design — CI, test fixtures and persistent machine credentials are meant to stay
unflagged — so the answer is to give the BFF's password path
its own **named, unflagged** `gateway.rbac` entry, not to widen the condition. `gateway.api_key`
then becomes genuinely emergency-only in an OIDC deployment, which is what this rule assumes rather
than what is true today, and the password path gains an attributable subject instead of `key:legacy`
as a side benefit. This is the concrete shape of the migration named under Consequences.

So the fix is conditional on deployment shape, not a blanket rule applied to the credential by
name: when OIDC is configured, `gateway.api_key` collapses into the same `break_glass: true`,
individually-attributed `gateway.rbac` model as `MCP_ADMIN_KEY` — one hardened mechanism, not
two parallel legacy paths each carrying a partial fix. When OIDC is absent, it remains the plain,
unhardened, primary authenticator it already is, and this ADR does not reach it. Either key may
remain as a first-deploy bootstrap fallback for the narrow window before any named entries
exist, the same shape of exception the provisioning workflow already accepts elsewhere, but
neither is the steady-state break-glass path, in an OIDC-configured deployment, once named
entries are provisioned.

## Consequences

- **Positive:** closes three of four properties ADR-0017 §4 requires and never designed — with
  property 3 met on the expiry half and deliberately **substituted** on the other, a review flag
  in place of the rate limit §4 asked for (see property 3 for why a call budget is the wrong
  shape for this credential);
  revocation scoped to individuals instead of the whole team; reuses the existing `gateway.rbac`
  schema and the ADR-0018 resolver rather than introducing new mechanisms; the audit subject for
  a break-glass action is now a specific, mandatory, configured name, the same precision
  principle already applied to `oidc:{issuer}#{sub}` for multi-issuer OIDC, extended to static
  credentials.
- **Negative / cost:** more entries to provision and rotate than a single shared value; custody
  verification requires either Kubernetes RBAC-inspection tooling in the deployment pipeline or,
  where that's not feasible, a manual signed-off gate — real infrastructure or process to build,
  not free. Consolidating two legacy key paths into one is itself a migration for any existing
  deployment already relying on `gateway.api_key`, not a purely additive change.
- **Follow-ups:** tune the 90-day expiry default and the reactivation-frequency flagging
  threshold from real usage once there's operating history (both ship as starting defaults, not
  final values — see property 3 above); extend the automated custody-verification check from
  property 1 to the console-level break-glass account as well, once its reissuance cycle is
  defined (the audit/expiry/attribution properties were already reconciled between the two
  mechanisms — see the UI spec's §6 — but this specific verification step is new here and hasn't
  been carried over yet).

## Alternatives considered

- **Leave `MCP_ADMIN_KEY` as-is, add only better audit logging for its use.** Rejected: audit
  logging alone cannot produce attribution from a credential that is shared by construction — it
  would record that "the admin key" was used, not by whom, which does not meet property 1 or 2
  even with better logging on top.
- **A single shared key with a mandatory sign-out/checkout log (whoever takes it writes their
  name down first).** Rejected: attribution that depends on the holder's own honesty at the
  moment they'd most want to avoid scrutiny is not a security property, and it doesn't survive
  the same "narrow test fixture, doesn't hold under real conditions" failure shape already found
  twice elsewhere in this codebase.
- **Rely on the tenant's own OIDC to cover the "IdP is unreachable" case instead of a separate
  static mechanism at all.** Rejected: it's circular — the scenario break-glass exists for is
  precisely the IdP being unreachable or broken. A path that only works when the normal identity
  system is healthy is not a break-glass path.

- **Harden `MCP_ADMIN_KEY` alone and leave `MCP_GATEWAY_API_KEY`/`gateway.api_key` as a separate,
  unflagged legacy path in every deployment.** Rejected as a blanket rule: it was the actual
  state of this ADR as first drafted, found in review to leave property 1 unmet specifically
  for OIDC-configured deployments, where the key is a genuine, undocumented second break-glass
  path. Not rejected as a *conditional* rule — where no OIDC is configured, this key is the
  deployment's ordinary authenticator, not break-glass, and is correctly left untouched; see the
  OIDC-configured/absent distinction under property 1 above.
