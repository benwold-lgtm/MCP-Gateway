# ADR-0022: Agent-initiated device writes are plan-bound, not standing access

- **Status:** Accepted
- **Date:** 2026-08-20
- **Related:** [rbac-roles.md](../rbac-roles.md) (`caller`/`operator` role split),
  [ADR-0018 §6](0018-device-credentials-by-reference.md) (plan digest, canonicalization,
  atomic validate-and-execute), [ADR-0017](0017-provider-authority-is-delegated.md)
  (elevated, time-boxed, named-act grant model; §7's session-binding treatment reused below),
  the SSRF guard (`device_mcp_gateway/security/url_policy.py`) — the human-review checkpoint
  this ADR's whole reasoning depends on

## Context

Today's RBAC model deliberately splits two capabilities across two different principals:
`operator` (human) holds `devices:write` but not `tools:call`; `caller` (agent/machine) holds
`tools:call` and `devices:read` but not `devices:write`. This is not an oversight — it mirrors
the same separation-of-duties pattern used elsewhere in this system (the `backup` machine role
is deliberately not `admin` for the identical reason: a scheduled job should not also be able to
invoke tools or edit the fleet).

`devices:write` gates `register_device`, which is the operation the SSRF guard's human-review
checkpoint exists to protect: vetting a new target against private-address checks and port
allowlists before it becomes something the gateway will call. Today a human performs that
vetting once, and every subsequent tool call an agent makes happens only against an
already-approved target. If `caller` held `devices:write`, the agent's own judgement — which
can be steered by prompt injection through tool output, a malicious device response, or a plain
bad inference — becomes the thing deciding whether a *new* target is trusted. The human
checkpoint that makes the SSRF guard meaningful would no longer exist by default for any agent
holding the role.

That reasoning is sound and is not being revisited here. The problem it creates is scope, not
correctness: an agent performing genuine intent-based infrastructure work — onboarding a device,
reconfiguring one, the IBN-controller use case discussed alongside this gateway — needs to
*propose and, once approved, execute* changes to the device registry itself, not only invoke
tools against things a human already registered by hand. A `caller` role that can never touch
the registry is permanently too narrow for that use case, and widening it unconditionally
reopens exactly the risk the split exists to prevent.

## Decision

`caller`'s baseline scope does not change. It remains `devices:read` + `tools:call`,
permanently, for every agent, by default.

A new elevated grant is introduced — **plan-bound**, not standing — reusing the plan-digest
mechanism ADR-0018 §6 specifies for restore, rather than inventing a second one:

1. **Propose** — an agent (directly, or via an IBN-controller-style automation acting through
   it) computes a plan describing the device registration(s) or reconfiguration(s) it wants,
   rendered in a form a human can review. This step requires no scope beyond `caller`'s existing
   baseline — proposing is read-and-simulate, the same reasoning already applied to restore's
   dry run: a non-destructive preview should not need elevated authority to run.

   **Propose must be purely local — no live outbound calls to an unregistered target, ever.**
   This is not a convenience simplification; it is what makes "no scope beyond baseline" true by
   construction rather than by accident. A useful plan for a *new* device registration would
   naturally want to probe the candidate target — confirm it's reachable, fetch its OpenAPI spec
   — but that is exactly the operation the SSRF guard exists to gate. Allowing propose to make
   that call under nothing more than `caller`'s baseline would hand any agent an unprivileged
   path to probe arbitrary internal addresses, dressed up as "just building a plan for review,"
   never touching `devices:write-planned` and never completing a registration. Propose may read
   existing registry state (`devices:read`, already baseline) and whatever the caller supplies
   inline as proposal parameters — it may never itself reach out to the candidate target while
   doing so.

   The cost of this restriction is worth stating plainly rather than glossing over: a human
   reviewing a plan is reviewing the agent's *claims* about a target, not gateway-confirmed
   reachability. If apply then fails the SSRF guard or another registration-time check, the
   human's approval doesn't survive contact with reality — they approved an attempt, not a
   guaranteed outcome. This is not a new kind of imprecision particular to this grant; it is
   exactly the relationship restore's own digest already has to its result — the digest
   guarantees fidelity between what was reviewed and what's attempted, never that the attempt
   succeeds.
2. **Review** — a human reviews the rendered plan. This produces a plan digest binding the
   entire canonicalized request, using the same canonicalization and whole-request-commitment
   rules ADR-0018 §6 already specifies — no new digest mechanism, no new canonicalization rules.

   **Approval also mints a separate artifact: the grant.** `devices:write-planned` is issued at
   this moment — not at Apply — scoped to this one digest specifically: valid only for an apply
   request carrying this exact digest, nothing broader. This is a distinct object from the
   digest itself, and the two must never collapse into one. Per ADR-0018 §6, a digest is a
   content-integrity commitment, never a capability — holding one confers no access. Apply
   therefore requires two independent things, matching restore's own shape exactly: a live,
   unexpired `devices:write-planned` grant scoped to that digest, *and* the digest itself
   re-validated against current inputs. Neither is sufficient alone.

   **The grant is its own approval artifact, carrying ADR-0017 §7's Tier 0 pending-request
   treatment** — session-bound delivery (returned only to the session that raised the original
   propose, closing the risk of the digest being intercepted or replayed by someone other than
   the proposer) and a bounded expiry, both reused rather than reinvented. What does **not**
   transfer is step-up: §7 records whether a grant was created under a step-up-verified session
   but deliberately cannot require it, and the cases it has in mind cross a trust boundary —
   reaching into another tenant's stack, or disclosing credentials. `devices:write-planned` does
   neither; it is entirely tenant-local, agent-to-its-own-registry. Importing step-up here would
   apply machinery calibrated for a materially higher-stakes crossing to something that isn't one.
3. **Apply** — the agent submits the apply request carrying that digest. The gateway confirms a
   live, unexpired `devices:write-planned` grant exists scoped to that exact digest, then
   validates the digest against current inputs and performs the write atomically, in the same
   single call, with no gap between check and write — identical to restore's treatment, for the
   identical reason (the DNS-rebind and stream-cursor precedents this project has already been
   burned by). A stale or altered digest is refused, not silently applied against different
   inputs; an apply with no matching grant is refused regardless of digest validity.
4. **Unattended reconciliation, bounded to exact repetition of a fact already vetted.** A fully
   unattended reconciliation loop may re-apply a plan without fresh human review only when the
   digest it would submit is byte-identical to a digest a human has already approved *for that
   same target*. This is a strict equality test, not a fuzzy "expected drift" classification —
   any difference at all, however small or routine-looking, requires the normal propose/review/
   apply path in full. A device reconnecting with the identical configuration a human already
   vetted is repeating a fact, not asking anyone to trust something new; a device proposing any
   different configuration is a new trust decision regardless of how it's framed.

   No new scope is introduced for this. `devices:write-planned` still gates it — the only
   change is that the grant issued at Review may, at the reviewer's explicit choice, be marked
   **repeatable** rather than single-use.

   **Single-use versus repeatable is a decision the reviewer makes at approval time, not
   something inferred from how long the grant's expiry happens to be set.** A normal approval is
   single-use — consumed by the one apply it authorizes, matching one review to one execution. A
   repeatable approval is a distinct, explicit choice: "approve this apply, and allow it to
   reconcile automatically until [date]." Keeping this an explicit reviewer decision, rather than
   deriving it from expiry length, keeps the human as the one opting a plan into repeatability —
   the same "the human is the check" principle ADR-0017 §7 itself is built on — rather than
   letting the system infer intent from a side effect.

   **A repeatable grant must itself have a bounded lifetime, with the same escalating-warning
   treatment already used for standing consent (ADR-0017 §3) and the break-glass credential
   (ADR-0023 property 3)**, rather than a silent, indefinite exemption from review. Bytes staying
   identical does not mean the operational context around them hasn't changed; a repeatable
   grant that never expires is a standing exemption from human review in everything but name,
   the same shape of risk those two ADRs both needed a maximum term to close. The specific
   duration is a follow-up, not decided here — see Consequences.

   **Worth flagging for later, not resolved here**: once repeatable, this grant shares one
   property with the break-glass credential — a normally-quiet mechanism that could start firing
   unusually often. ADR-0023 property 3's reactivation-frequency flagging (flag unusual reuse,
   don't hard-block) is a plausible fit if a repeatable approval starts reconciling far more
   often than expected, but this isn't specified as part of this decision.

**The scope is named `devices:write-planned`.** This follows the `resource:action` shape every
other scope in this system already uses, extended the same way `backup:export-portable`
qualifies `backup:export` rather than inventing a third colon segment. "Planned" ties the name
directly to the mechanism it depends on — the plan digest from ADR-0018 §6 — rather than to who
holds it; naming by principal (e.g. `devices:write-agent`) would describe the wrong thing, since
the actual security property is plan-binding, not machine-versus-human, and a future human-driven
bulk-change workflow wanting the same plan-bound pattern shouldn't require a rename to use it.

**`devices:write-planned` must not appear in `ROLE_SCOPES`.** That table is for standing
bundles — `caller`, `operator`, and the rest are always-on for as long as the role is held. This
scope is explicitly not standing; it must be issued only at Review, scoped to the one digest that
approval produced — never minted by, or collapsed into, the digest-validation step at Apply.
Stated here directly so a future change doesn't "helpfully" add it to a role's static scope list,
or simplify the two checks into one, and reopen the exact standing-access or digest-as-capability
problems this ADR exists to prevent.

The grant authorizes exactly the reviewed plan — nothing else. It is not standing
`devices:write`, and it does not authorize any registration or change outside what a human
already looked at.

**The SSRF guard and every other registration-time check still run in full on the actual
write.** This mechanism adds a human-reviewed, digest-bound gate in *front of* that checkpoint;
it does not replace or weaken it — the same relationship restore's dry-run-then-apply has to the
fail-closed key-mismatch preflight it sits in front of.

## Consequences

- **Positive:** unlocks agent-driven infrastructure changes (the IBN use case) without widening
  the permanent blast radius of a compromised, manipulated, or simply wrong agent. Reuses
  specified machinery — plan digest, canonicalization, atomic validate-and-execute, ADR-0017
  §7's session-binding — instead of inventing new mechanisms. Preserves the human checkpoint the SSRF guard depends
  on for meaning. Consistent with the separation-of-duties pattern already used for
  `operator`/`caller` and for the `backup` role. Unattended reconciliation is now possible for a
  mature IBN loop's routine, expected corrections without weakening review for anything actually
  new — the exact-digest-equality bound means an agent (or a compromised one) cannot use
  "reconciliation" as cover to slip a changed target past review, since any difference at all
  falls back to the full propose/review/apply path.

- **Negative / cost:** this reintroduces a form of the elevated-grant taxonomy ADR-0018 §6 had
  just simplified — worth being explicit that it sits on a *different axis*. §6 removed
  credential-bearing grants because backup archives stopped carrying live secrets; this grant is
  about registry-mutation blast radius, which was never about credential exposure and is not
  affected by that simplification. It should not be read as reopening §6's decision. Separately,
  a plan built without live target verification (see Decision, step 1) means an approved plan
  can still fail at apply time against checks that only run against a real, reachable target —
  review quality is bounded by what the agent could truthfully claim, not by gateway-confirmed
  fact. Persisting approved digests for reconciliation is additional state the gateway now
  carries per target, with its own expiry to manage — not free, though small relative to the
  alternative of either no unattended reconciliation at all or an unbounded standing exemption.

- **This distinction — grant minted at Review, kept separate from the digest — was initially
  under-specified.** An earlier draft described the grant as issued by digest validation itself
  at Apply, which is the digest-as-capability collapse ADR-0018 §6 explicitly rules out. Caught
  and corrected before implementation by checking directly against §6's own table rather than
  assuming the two designs were consistent.

- **Follow-ups:** decide the specific maximum age for a persisted, reconciliation-eligible
  approval and the corresponding warning schedule (data-dependent, same treatment already given
  to the 90-day break-glass expiry in ADR-0023 property 3 — ships as a default, tuned from real
  usage rather than fixed permanently here); consider whether ADR-0023's reactivation-frequency
  flagging is worth extending to repeatable grants under this ADR, once there's operating history
  to judge it against.

## Alternatives considered

- **Widen `caller`'s baseline to include `devices:write` outright.** Rejected: removes the human
  review checkpoint by default, permanently, for every agent — the exact regression the SSRF
  guard's design exists to prevent. A compromised or manipulated agent could register an
  arbitrary new target.

- **A separate, always-standing role for agents that need write access** (mirroring how `backup`
  is separate from `operator`). Rejected: standing authority reviews *who* may make changes,
  once, at role-grant time — it does not review the *content* of each change. Plan-binding
  reviews the actual proposed change every time, which is the stronger and more relevant
  guarantee here.

- **Status quo — a human manually mirrors every agent-proposed change into the console
  themselves.** Rejected as the reason this ADR exists: it does not scale to real intent-based
  automation and defeats the purpose of agent-driven configuration in the first place.

- **Let propose make a live probe of the candidate target**, so the human reviews
  gateway-confirmed reachability rather than an agent's claim. Rejected: this is the SSRF guard's
  own checkpoint reached through an unprivileged, unnamed side door — any agent could use
  "proposing a plan" as cover to probe arbitrary internal addresses without ever holding
  `devices:write-planned` or completing a registration. The accuracy this would buy a plan's
  review is not worth reopening the exact risk this ADR exists to prevent.

- **A pre-approved plan "shape" or template for unattended reconciliation** (e.g., "anything
  matching this device type may auto-register"), rather than exact digest equality to one
  specific, previously-vetted approval. Rejected: a pattern match is functionally
  indistinguishable from handing `devices:write` back to any agent for changes that fit the
  pattern — it reopens the exact risk this ADR exists to prevent, with extra steps in between.
  Exact equality to a fact a human already vetted is precise and ungameable in the way a
  pattern is not.

- **Issue the grant at Apply, from digest validation itself**, rather than at Review. Rejected:
  this is the digest-as-capability collapse ADR-0018 §6 explicitly rules out — holding a digest
  would then confer access, contradicting §6's own table ("holding it gets you: nothing"). Also
  loses session-binding as a coherent concept, since there would be no approval event distinct
  from the digest to bind a session to.
