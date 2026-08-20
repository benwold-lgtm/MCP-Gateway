# ADR-0022: Agent-initiated device writes are plan-bound, not standing access

- **Status:** Proposed
- **Date:** 2026-08-20
- **Related:** [rbac-roles.md](../rbac-roles.md) (`caller`/`operator` role split),
  [ADR-0018 §6](0018-device-credentials-by-reference.md) (plan digest, canonicalization,
  atomic validate-and-execute), [ADR-0017](0017-provider-authority-is-delegated.md)
  (elevated, time-boxed, named-act grant model)

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
2. **Review** — a human reviews the rendered plan. This produces a plan digest binding the
   entire canonicalized request, using the same canonicalization and whole-request-commitment
   rules ADR-0018 §6 already specifies — no new digest mechanism, no new canonicalization rules.
3. **Apply** — the agent submits the apply request carrying that digest. The gateway validates
   the digest against current inputs and performs the write atomically, in the same single call,
   with no gap between check and write — identical to restore's treatment, for the identical
   reason (the DNS-rebind and stream-cursor precedents this project has already been burned by).
   A stale or altered digest is refused, not silently applied against different inputs.

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
  specified machinery — plan digest, canonicalization, atomic validate-and-execute — instead of
  a second bespoke mechanism. Preserves the human checkpoint the SSRF guard depends on for
  meaning. Consistent with the separation-of-duties pattern already used for `operator`/`caller`
  and for the `backup` role.

- **Negative / cost:** this reintroduces a form of the elevated-grant taxonomy ADR-0018 §6 had
  just simplified — worth being explicit that it sits on a *different axis*. §6 removed
  credential-bearing grants because backup archives stopped carrying live secrets; this grant is
  about registry-mutation blast radius, which was never about credential exposure and is not
  affected by that simplification. It should not be read as reopening §6's decision.

- **The unresolved tension, named rather than smoothed over:** this design assumes a human
  reviews each plan before it's applied. A fully unattended reconciliation loop — the actual end
  state of a mature IBN system, continuously correcting drift against declared intent — wants
  most of its routine corrections to require no human in the loop at all. Requiring fresh review
  on every drift-correction plan does not scale to that model; skipping review for registry
  writes contradicts the reason this ADR exists. The likely direction, not decided here: bounded,
  expected drift-correction (e.g., re-registering a device that dropped and reappeared with
  identical configuration) may warrant a pre-approved plan *shape* that doesn't require fresh
  review each occurrence, while any genuinely novel registration always requires it. This
  distinction needs its own follow-up before an unattended reconciliation loop can be built on
  top of this grant.

- **Follow-ups:** name the actual scope/grant identifier; confirm proposing (the dry-run
  equivalent) requires no scope beyond `caller`'s baseline; resolve the bounded-vs-novel-change
  distinction above before any unattended/scheduled use of this grant is built.

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

## Open questions

> Added on review, 2026-08-20, checked against the code at `a92315e`. The first is a
> **correctness gap in the design**, not a scheduling matter; the rest are ordering and scope.

- **⚠️ The digest does not carry authorization, and this design needs it to.** ADR-0018 §6 is
  explicit that the digest *"is an integrity commitment, not a capability"* — holding one "gets
  you **nothing**", and it *"constrains **an** apply to match **a** preview; it establishes
  nothing about who reviewed what."* §6 goes further and states that two-person review is "not a
  property this provides, and it is **not wanted**."

  That is safe for restore because the applier **already holds `backup:write`**: the digest only
  has to prove the instruction was not altered. This ADR inverts that premise — its whole point
  is that the agent holds *no* standing `devices:write` — so here the digest would have to be
  what turns an unprivileged proposal into an authorized write. It cannot be, by §6's own
  design.

  So step 2 needs an object §6 deliberately does not produce: an **approval artifact** issued by
  the reviewing human and bound to the digest. That object *is* capability-shaped — holding it
  gets you a write — which means it inherits the treatment [ADR-0017](0017-provider-authority-is-delegated.md)
  §7 gives its pending-request id (session binding, expiry, single named act) rather than the
  deliberately unbound treatment §6 gives the digest. **The digest identifies the plan; the
  approval authorizes it.** Conflating them is the one thing this design must not do, and the
  ADR as written reads as though the digest does both.

- **Neither dependency exists yet.** The plan digest is **specified but not built** — `grep
  plan_digest` over `device_mcp_gateway/` and `tests/` returns nothing; ADR-0018 §6 and PR #136
  pin its algorithm (SHA-256, hex lowercase), canonicalization (RFC 8785 + absent→omitted +
  sorted set-valued fields) and field name, and that is all. And there is **no propose/preview
  path for device writes at all**: `POST /v1/devices` has no `dry_run`, so step 1 is new surface
  rather than reuse. This ADR is therefore blocked behind ADR-0018's backup-simplification slice,
  and should say so rather than reading as though the machinery were waiting to be called.

- **What is the reviewed artifact, exactly?** Restore's plan is derived from an archive the
  caller supplies. A device-registration plan has no equivalent input document, so "the
  canonicalized request" needs defining for this path before §6's whole-request-commitment rule
  can be applied to it — including whether one plan may carry several device writes, and whether
  a partially-applicable plan is refused whole or applied in part.

- **Does the SSRF guard's checkpoint actually move?** The ADR states the guard still runs in full
  at write time, which is right. Worth confirming the intended reading: the human is reviewing a
  *proposed* target before the guard has passed judgement on it, so a plan can be approved and
  then still refused at apply. That is the correct order, but it means an approved plan is not a
  promise of success, and the failure needs to surface as a refusal with a named reason rather
  than as a silently dropped device.
