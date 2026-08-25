# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Propose/Review/Apply for agent-initiated device writes (ADR-0022).

This slice is Propose only. `caller`'s baseline (`devices:read` + `tools:call`) never
gains `devices:write` — instead an agent proposes a plan here, a human reviews and
approves it (a later slice), and the agent applies by redeeming the grant that approval
mints (another later slice).

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

from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.cfg import write_planned_proposal_ttl_seconds
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.rbac import SCOPE_DEVICES_READ, require_scope
from device_mcp_gateway.shared.canonical_json import compute_digest
from device_mcp_gateway.write_planned import pending_proposal_store

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
