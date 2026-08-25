# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Propose/Review/Apply for agent-initiated device writes (ADR-0022).

This slice adds Review to Propose. `caller`'s baseline (`devices:read` + `tools:call`)
never gains `devices:write` — instead an agent proposes a plan (above), a human reviews
and approves it (below), and the agent applies by redeeming the grant that approval mints
(a later slice).

**Review is gated by `devices:write`, not a new scope.** `operator` already holds it, and
approving a device-registry change is squarely inside what that scope already means — the
same reasoning `backup:export-portable` uses to justify *not* inventing a scope where an
existing one already covers the authority. `devices:write-planned` itself is minted here,
never checked here: Review is the one place that scope's whole meaning comes from.

**The grant is bound to the *proposer's* subject, never the reviewer's.** `approve_device_plan`
reads `proposal.subject` (whoever called Propose) and issues the grant to that identity —
this is ADR-0017 §7's "session-bound delivery" property, reduced to what it actually needs
here: Apply must be the same caller who proposed, not whoever happens to review. A reviewer
approving their own proposal (self-service) is not prevented by this route — that is a
policy question for how `devices:write` is provisioned, not a mechanism this ADR changes.

**A proposal is one-shot.** Approve deletes it immediately after issuing the grant, so it
cannot be approved a second time — a stale double-click, or a reviewer plus an automation
racing the same proposal, produces exactly one grant, never two.

**Propose is purely local — no live outbound call to the candidate target, ever, and no
call into `validate_device_registration`/`_check_target_url` (the SSRF guard) either.**
This is the ADR's own load-bearing restriction, not a convenience cut: a useful
registration plan would naturally want to probe the candidate target to confirm it is
reachable, and that is exactly the operation the SSRF guard exists to gate. Allowing
Propose to make that call under nothing more than `caller`'s baseline would hand any
agent an unprivileged path to probe arbitrary internal addresses, dressed up as "just
building a plan for review." The real validation — SSRF guard included — runs in full at
Apply, against the extracted `register_device`/`update_device` logic, not here.

For the same reason, Propose does not reuse `register_device`/`update_device`'s deep
parsing helpers (`_parse_auth`, `_read_upstream`, ...): duplicating that parsing here
would either drift from the real thing or become the second source of truth for what a
valid plan looks like. Propose does only the shape-level sanity a plan needs to be worth
a human's time to review — a well-formed `intent` and a named target — and lets Apply be
the one place a plan is actually validated.

The digest commits to the **whole submitted body**, not an enumerated field list — the
same principle ADR-0018 §6 applies to restore's plan_digest, and the reason the
checkpoint note for this ADR explicitly warns against mirroring the console's
`signatureOf`-style enumerated signature server-side.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from device_mcp_gateway.api.devices import _apply_register, _apply_update
from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.cfg import (
    write_planned_grant_ttl_seconds,
    write_planned_proposal_ttl_seconds,
    write_planned_repeatable_max_seconds,
)
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.rbac import SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, require_scope
from device_mcp_gateway.shared.canonical_json import compute_digest
from device_mcp_gateway.write_planned import pending_proposal_store, write_planned_grant_store

router = APIRouter()

#: The only two kinds of plan this mechanism covers today (ADR-0022's "registration(s) or
#: reconfiguration(s)"). A third intent is a new route decision, not a value to add here
#: quietly — `register_device`/`update_device` have different required fields.
INTENT_REGISTER = "register"
INTENT_UPDATE = "update"
_INTENTS = (INTENT_REGISTER, INTENT_UPDATE)

# A proposal is registry:read-adjacent work (it writes only to the proposal store, never
# to the device registry) but still creates server-side state, so it gets its own budget
# rather than riding on devices:read's implicit "free" reads — the same reasoning restore's
# preview route already applies to itself.
_PROPOSE_LIMITS = [
    Depends(rate_limit("30/minute", "write_planned_propose")),
    Depends(rate_limit_principal("60/minute", "write_planned_propose")),
]


@router.post(
    "/devices/plans",
    dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))] + _PROPOSE_LIMITS,
)
async def propose_device_plan(request: Request):
    """Render a device-write plan and return its digest. Writes nothing, reaches nothing.

    Body: ``{intent: "register"|"update", hostname, ...}`` — the same fields
    `register_device`/`update_device` accept; only `intent` and `hostname` (and
    `base_url`, for a new registration) are checked here. Response:
    ``{proposal_id, plan, plan_digest, expires_at}``. `proposal_id` is what a reviewer
    reads back (a later slice); `plan_digest` is what Apply will recompute and compare
    against.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    intent = data.get("intent")
    if intent not in _INTENTS:
        raise HTTPException(status_code=400, detail=f"'intent' must be one of: {', '.join(_INTENTS)}")
    hostname = data.get("hostname")
    if not hostname:
        raise HTTPException(status_code=400, detail="'hostname' is required")
    if intent == INTENT_REGISTER and not data.get("base_url"):
        raise HTTPException(status_code=400, detail="'base_url' is required to register a new device")

    digest = compute_digest(data)
    principal = request.state.principal
    store = pending_proposal_store(request.app.state)
    ttl = write_planned_proposal_ttl_seconds(request.app.state.config)
    proposal_id = await store.create(subject=principal.subject, digest=digest, plan=data, ttl_seconds=ttl)
    # Read back rather than computing `time.time() + ttl` a second time here — the store is
    # the one source of truth for when this proposal actually expires.
    proposal = await store.get(proposal_id)

    audit_request(
        request,
        "device.write_planned.propose",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=hostname,
        intent=intent,
        plan_digest=digest,
    )
    return {
        "proposal_id": proposal_id,
        "plan": data,
        "plan_digest": digest,
        "expires_at": proposal.expires_at if proposal is not None else None,
    }


@router.get(
    "/devices/plans/{proposal_id}",
    dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))],
)
async def get_device_plan(proposal_id: str, request: Request):
    """What a reviewer reads before deciding. Writes nothing."""
    store = pending_proposal_store(request.app.state)
    proposal = await store.get(proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="No such proposal, or it has expired; propose again")
    return {
        "proposal_id": proposal_id,
        "plan": proposal.plan,
        "plan_digest": proposal.digest,
        "expires_at": proposal.expires_at,
    }


def _approval_ttl(config: dict, *, repeatable: bool, requested: object) -> int:
    """The grant's lifetime: the deployment's configured ceiling for this grant kind,
    shortened if the reviewer asked for less, never lengthened beyond it.

    A repeatable grant's ceiling is `write_planned_repeatable_max_seconds` — deliberately
    the same cap regardless of what the reviewer requests, since ADR-0022 §4 requires a
    repeatable grant to have *some* bounded maximum and leaves the exact value to
    operating history, not to a per-approval choice that could quietly grow unbounded.
    """
    ceiling = write_planned_repeatable_max_seconds(config) if repeatable else write_planned_grant_ttl_seconds(config)
    if requested is None:
        return ceiling
    if isinstance(requested, bool) or not isinstance(requested, (int, float)) or requested <= 0:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be a positive number")
    return int(min(float(requested), ceiling))


@router.post(
    "/devices/plans/{proposal_id}/approve",
    dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))],
)
async def approve_device_plan(proposal_id: str, request: Request):
    """Mint a `devices:write-planned` grant for the proposal's own proposer, scoped to its
    digest. One-shot: the proposal is consumed here whether or not it is ever applied.

    Body (all optional): ``{"repeatable": bool, "ttl_seconds": number}``. `repeatable`
    (default `false`) is the reviewer's *explicit* choice per ADR-0022 §4 — never inferred
    from `ttl_seconds` or anything else. `ttl_seconds`, if given, shortens the grant below
    the deployment's configured ceiling for its kind; it can never lengthen it.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    repeatable = bool(body.get("repeatable", False))
    ttl = _approval_ttl(request.app.state.config, repeatable=repeatable, requested=body.get("ttl_seconds"))

    proposals = pending_proposal_store(request.app.state)
    proposal = await proposals.get(proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="No such proposal, or it has expired; propose again")

    grants = write_planned_grant_store(request.app.state)
    reviewer = request.state.principal.subject
    grant = await grants.issue(
        digest=proposal.digest,
        subject=proposal.subject,
        reviewer_subject=reviewer,
        repeatable=repeatable,
        ttl_seconds=ttl,
    )
    # One-shot, regardless of what happens next: a proposal cannot be approved twice, and a
    # digest that already has a live grant behind it gains nothing from a second approval.
    await proposals.delete(proposal_id)

    audit_request(
        request,
        "device.write_planned.approve",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=proposal.plan.get("hostname"),
        plan_digest=proposal.digest,
        proposer_subject=proposal.subject,
        repeatable=repeatable,
        grant_ttl_seconds=ttl,
    )
    return {"plan_digest": grant.digest, "repeatable": grant.repeatable, "expires_at": grant.expires_at}


# Apply reaches the registry, same as a direct register_device/update_device call, so it
# gets that route's own budget rather than riding on devices:read's implicit "free" reads.
_APPLY_LIMITS = [
    Depends(rate_limit("60/minute", "write_planned_apply")),
    Depends(rate_limit_principal("120/minute", "write_planned_apply")),
]


@router.post(
    "/devices/plans/apply",
    dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))] + _APPLY_LIMITS,
)
async def apply_device_plan(request: Request):
    """Redeem a `devices:write-planned` grant and perform exactly the write it names.

    Body: the full plan exactly as proposed — the gateway persists no plan content between
    Propose and Apply (the same property restore's own apply already holds), so Apply
    resubmits it whole. The digest is recomputed from this body and checked against a live
    grant for the caller's own subject *before* anything else runs: a missing, expired,
    already-consumed, or wrong-subject grant is refused (`403 ERR_PLAN_STALE`), and so is a
    body that no longer digests to what was reviewed — a plan edited after Review is a new
    plan, not the one the grant covers.

    Only once redemption succeeds does `register_device`/`update_device`'s own validation
    run — SSRF guard included — via the identical internal functions those routes call, so
    a valid grant is never a rubber stamp past those gates.

    A single-use grant is consumed by redemption itself, not by a successful write: this is
    what closes the check/write race (two concurrent Applies must not both see an
    unconsumed grant), the same way restore's own apply closes its. The cost is that a
    single-use grant spent on a plan that then fails validation is gone — Propose and Review
    again, don't retry the same Apply. A **repeatable** grant has no such cost: it is never
    consumed, so a validation failure changes nothing and the identical Apply can simply be
    retried once the plan is fixed.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    intent = data.get("intent")
    if intent not in _INTENTS:
        raise HTTPException(status_code=400, detail=f"'intent' must be one of: {', '.join(_INTENTS)}")
    hostname = data.get("hostname")
    if not hostname:
        raise HTTPException(status_code=400, detail="'hostname' is required")

    digest = compute_digest(data)
    principal = request.state.principal
    grants = write_planned_grant_store(request.app.state)
    result = await grants.check_and_consume(digest=digest, subject=principal.subject)
    if not result.ok:
        audit_request(
            request,
            "device.write_planned.apply",
            outcome=AUDIT_OUTCOME_DENIED,
            target=hostname,
            plan_digest=digest,
            reason=result.reason,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "ERR_PLAN_STALE",
                "message": (
                    "No live devices:write-planned grant matches this exact plan for your "
                    "identity (it may be missing, expired, already used, reviewed for a "
                    "different plan, or reviewed for a different caller). Propose again and "
                    "have it reviewed."
                ),
                "reason": result.reason,
            },
        )

    grant = result.grant
    if intent == INTENT_REGISTER:
        outcome = await _apply_register(data, request)
    else:
        outcome = await _apply_update(hostname, data, request)

    audit_request(
        request,
        "device.write_planned.apply",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=hostname,
        plan_digest=digest,
        reviewer_subject=grant.reviewer_subject if grant is not None else None,
        repeatable=grant.repeatable if grant is not None else None,
    )
    return outcome
