# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Raise / decide / list / revoke support requests and grants (ADR-0017, slice 1).

Every route here is gated by `support:administer` — the scope that gates *administering the
mechanism itself*, not the tenant-vocabulary scopes (`devices:read`, `tools:call`, ...) a
support grant actually carries once issued. In this build (pre-ADR-0021), the same BFF process
mediates both the provider-plane raise and the tenant-plane decide/list/revoke, so the gateway
does not need to distinguish "a provider operator is asking" from "a tenant admin is asking" at
the scope level — that distinction is enforced one layer up, in the BFF's own session planes.

**Standing consent is not a different mechanism, only a different trigger (§3).** Raising a
request under an active, matching standing-consent setting still creates a `PendingSupportRequest`
and immediately marks it approved with a self-issued grant — the caller always raises, then
polls, exactly as it would for a request a human approved. The only thing standing consent
changes is how fast the first poll answers.

**Revoke is idempotent (§8).** A tenant admin clicking revoke on a grant that already ended
(naturally expired, or revoked from another tab) must see the same success, not an error — the
whole point of "the tenant gains a control they did not have" is a button that always works.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.cfg import (
    support_grant_ttl_seconds,
    support_request_ttl_seconds,
    support_self_issue_review_threshold,
    support_self_issue_review_window_days,
    support_standing_consent_max_seconds,
)
from device_mcp_gateway.rbac import ALL_SCOPES, SCOPE_DEVICES_WRITE_PLANNED, SCOPE_SUPPORT_ADMINISTER, require_scope
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.support_grant_inflight import support_grant_inflight_registry
from device_mcp_gateway.support_grant_pop import InvalidPublicKey, parse_public_key
from device_mcp_gateway.support_grants import (
    pending_support_request_store,
    self_issue_activity_tracker,
    standing_consent_store,
    support_grant_store,
)
from device_mcp_gateway.tenant_notifications import tenant_notification_store

router = APIRouter(dependencies=[Depends(require_scope(SCOPE_SUPPORT_ADMINISTER))])

#: The closed vocabulary a support grant's scopes may be drawn from — the tenant's own
#: vocabulary (ADR-0017 §2), never a provider vocabulary (there isn't one in this gateway).
#: Excludes `support:administer` itself (a support grant must not be able to mint the power to
#: administer more support grants — that is a privilege-escalation shape, not a support
#: session) and `devices:write-planned` (which by design is never held via any standing or
#: administered mechanism, only minted per-plan at Review; ADR-0022's own rule, unchanged here).
GRANTABLE_SUPPORT_SCOPES = ALL_SCOPES - {SCOPE_SUPPORT_ADMINISTER, SCOPE_DEVICES_WRITE_PLANNED}

_MAX_JUSTIFICATION = 2000

_RAISE_LIMITS = [
    Depends(rate_limit("30/minute", "support_request_raise")),
    Depends(rate_limit_principal("60/minute", "support_request_raise")),
]
# Generous: a polling loop legitimately calls this every second or two while a request is
# pending, and refusing that is refusing the mechanism's own normal operation.
_POLL_LIMITS = [
    Depends(rate_limit("120/minute", "support_request_poll")),
    Depends(rate_limit_principal("240/minute", "support_request_poll")),
]


def _validate_scopes(requested: object) -> frozenset[str]:
    if not isinstance(requested, list) or not requested or not all(isinstance(s, str) for s in requested):
        raise HTTPException(status_code=400, detail="'requested_scopes' must be a non-empty list of strings")
    scopes = frozenset(requested)
    unknown = scopes - GRANTABLE_SUPPORT_SCOPES
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"scope(s) not grantable via a support grant: {sorted(unknown)}",
        )
    return scopes


@router.post("/support-requests", status_code=201)
async def raise_support_request(request: Request):
    """A provider operator raises a request. `provider_subject` is attribution only — it is
    recorded, and it is the only identity the poll below will ever deliver a decision to; it
    authorizes nothing by itself (ADR-0017 §2).

    An optional `public_key` (base64 Ed25519) is the operator's opt-in to Tier 1 (§7):
    submitting one asks that the resulting grant be sender-constrained — every subsequent
    request must also carry a valid, fresh signature over itself. Omitting it requests the
    Tier 0 floor, a plain bearer."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    provider_subject = body.get("provider_subject")
    if not isinstance(provider_subject, str) or not provider_subject.strip():
        raise HTTPException(status_code=400, detail="'provider_subject' is required")
    justification = body.get("justification")
    if not isinstance(justification, str) or not justification.strip():
        raise HTTPException(status_code=400, detail="'justification' is required")
    if len(justification) > _MAX_JUSTIFICATION:
        raise HTTPException(status_code=400, detail=f"'justification' must be at most {_MAX_JUSTIFICATION} chars")
    scopes = _validate_scopes(body.get("requested_scopes"))
    public_key = body.get("public_key")
    if public_key is not None:
        if not isinstance(public_key, str):
            raise HTTPException(status_code=400, detail="'public_key' must be a string")
        try:
            parse_public_key(public_key)
        except InvalidPublicKey as exc:
            raise HTTPException(status_code=400, detail=f"'public_key' is invalid: {exc}") from exc

    request_store = pending_support_request_store(request.app.state)
    ttl = support_request_ttl_seconds(request.app.state.config)
    request_id = await request_store.create(
        provider_subject=provider_subject,
        requested_scopes=scopes,
        justification=justification,
        ttl_seconds=ttl,
        public_key=public_key,
    )
    # Captured now, while the request is still "pending" — `get()` deliberately only ever
    # sees a pending request (its own contract, matching the reviewer-facing routes below),
    # so reading it again *after* a possible self-issue below would see nothing and silently
    # null this out.
    pending = await request_store.get(request_id)
    expires_at = pending.expires_at if pending is not None else None

    consent = await standing_consent_store(request.app.state).get()
    self_issued = consent is not None and scopes <= consent.scopes
    if self_issued:
        grants = support_grant_store(request.app.state)
        grant = await grants.issue(
            provider_subject=provider_subject,
            scopes=scopes,
            ttl_seconds=support_grant_ttl_seconds(request.app.state.config),
            self_issued=True,
            bound_public_key=public_key,
        )
        await request_store.mark_approved(request_id, grant_id=grant.id, credential=grant.id)
        await _flag_frequent_self_issue(request, provider_subject)

    # `justification` is recorded here, once, in the tenant's own audit chain — and nowhere
    # in any API response from here on (§2: "recorded once and never echoed back").
    audit_request(
        request,
        "support_grant.raise",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=provider_subject,
        requested_scopes=sorted(scopes),
        justification=justification,
        self_issued=self_issued,
    )
    return {"request_id": request_id, "requested_scopes": sorted(scopes), "expires_at": expires_at}


async def _flag_frequent_self_issue(request: Request, provider_subject: str) -> None:
    """ADR-0017 slice 5: a self-issued grant had no per-instance human approval — flag it if
    ``provider_subject`` is self-issuing often enough that standing consent has become
    unreviewed blanket access, the same "an unattended path used this routinely" signal
    `breakglass.py`'s reactivation flag already gives the tenant for the other silent path.

    Never blocks — same invariant as break-glass's own flag: this only ever informs."""
    window_days = support_self_issue_review_window_days(request.app.state.config)
    threshold = support_self_issue_review_threshold(request.app.state.config)
    tracker = self_issue_activity_tracker(request.app.state)
    activity = await tracker.record(provider_subject, window_seconds=window_days * 86400)
    if activity.count_in_window <= threshold:
        return

    audit_request(
        request,
        "support_grant.standing_consent.frequent_self_issue",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=provider_subject,
        level="WARNING",
        severity="high",
        self_issues_in_window=activity.count_in_window,
        review_window_days=window_days,
        signal_degraded=activity.degraded,
    )
    await tenant_notification_store(request.app.state).create(
        kind="support_grant.frequent_self_issue",
        subject=provider_subject,
        message=(
            f"{provider_subject} has self-issued a support grant under standing consent "
            f"{activity.count_in_window} time(s) in the last {window_days} day(s) — none of "
            "them reviewed by a person. If this is more than expected, review the standing-"
            "consent setting."
        ),
        severity="warning",
    )


@router.get("/support-requests")
async def list_pending_support_requests(request: Request):
    """What the tenant console's inbox reads. A read — unaudited, like `GET .../plans/{id}`."""
    request_store = pending_support_request_store(request.app.state)
    pending = await request_store.list_pending()
    return {
        "requests": [
            {
                "request_id": p.request_id,
                "provider_subject": p.provider_subject,
                "requested_scopes": sorted(p.requested_scopes),
                "justification": p.justification,
                "created_at": p.created_at,
                "expires_at": p.expires_at,
            }
            for p in pending
        ]
    }


# --- standing consent (§3) ----------------------------------------------------------------
#
# Registered before `/support-requests/{request_id}` below, deliberately: Starlette matches
# routes in registration order, and "standing-consent" would otherwise be swallowed by that
# route's `{request_id}` path parameter. See test_support_requests.py for the regression test
# this ordering exists to keep passing.


@router.get("/support-requests/standing-consent")
async def get_standing_consent(request: Request):
    consent = await standing_consent_store(request.app.state).get()
    if consent is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "scopes": sorted(consent.scopes),
        "enabled_by": consent.enabled_by,
        "enabled_at": consent.enabled_at,
        "expires_at": consent.expires_at,
    }


@router.post("/support-requests/standing-consent", status_code=201)
async def enable_standing_consent(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    scopes = _validate_scopes(body.get("scopes"))
    ceiling = support_standing_consent_max_seconds(request.app.state.config)
    requested_ttl = body.get("ttl_seconds")
    if requested_ttl is not None:
        if isinstance(requested_ttl, bool) or not isinstance(requested_ttl, (int, float)) or requested_ttl <= 0:
            raise HTTPException(status_code=400, detail="'ttl_seconds' must be a positive number")
        ttl = int(min(float(requested_ttl), ceiling))
    else:
        ttl = ceiling

    enabled_by = request.state.principal.subject
    consent = await standing_consent_store(request.app.state).enable(
        scopes=scopes, enabled_by=enabled_by, ttl_seconds=ttl
    )
    audit_request(
        request,
        "support_grant.standing_consent.enable",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=enabled_by,
        scopes=sorted(scopes),
        expires_at=consent.expires_at,
    )
    return {"scopes": sorted(consent.scopes), "enabled_by": consent.enabled_by, "expires_at": consent.expires_at}


@router.delete("/support-requests/standing-consent", status_code=204)
async def disable_standing_consent(request: Request):
    disabled = await standing_consent_store(request.app.state).disable()
    if disabled:
        audit_request(
            request,
            "support_grant.standing_consent.disable",
            outcome=AUDIT_OUTCOME_SUCCESS,
            target=request.state.principal.subject,
        )


@router.get("/support-requests/{request_id}", dependencies=_POLL_LIMITS)
async def poll_support_request(request: Request, request_id: str, provider_subject: str = Query(...)):
    """The raising session's own view. Scoped strictly to `provider_subject` — a mismatch
    reads exactly like the request never existed (§7: never "found but not yours")."""
    request_store = pending_support_request_store(request.app.state)
    result = await request_store.poll(request_id, provider_subject=provider_subject)
    if result.status is None:
        raise HTTPException(status_code=404, detail="No such request, it has expired, or it was already delivered")
    body: dict = {"status": result.status}
    if result.status == "approved":
        body["grant_id"] = result.grant_id
        body["credential"] = result.credential
    return body


@router.post("/support-requests/{request_id}/approve")
async def approve_support_request(request: Request, request_id: str):
    request_store = pending_support_request_store(request.app.state)
    pending = await request_store.get(request_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="No such request, or it has expired")

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    requested_ttl = body.get("ttl_seconds")
    ceiling = support_grant_ttl_seconds(request.app.state.config)
    if requested_ttl is not None:
        if isinstance(requested_ttl, bool) or not isinstance(requested_ttl, (int, float)) or requested_ttl <= 0:
            raise HTTPException(status_code=400, detail="'ttl_seconds' must be a positive number")
        ttl = int(min(float(requested_ttl), ceiling))
    else:
        ttl = ceiling

    grants = support_grant_store(request.app.state)
    grant = await grants.issue(
        provider_subject=pending.provider_subject,
        scopes=pending.requested_scopes,
        ttl_seconds=ttl,
        step_up_verified=bool(body.get("step_up_verified", False)),
        bound_public_key=pending.public_key,
    )
    delivered = await request_store.mark_approved(request_id, grant_id=grant.id, credential=grant.id)
    if not delivered:
        # Someone else decided it first (or it expired) between our `get` and now — the grant
        # we just minted is orphaned, so revoke it immediately rather than leaving a live,
        # undelivered credential behind.
        await grants.revoke(grant.id)
        raise HTTPException(status_code=409, detail="This request was already decided, or has expired")

    audit_request(
        request,
        "support_grant.approve",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=pending.provider_subject,
        request_id=request_id,
        grant_id=grant.id,
        scopes=sorted(grant.scopes),
        expires_at=grant.expires_at,
    )
    return {"grant_id": grant.id, "expires_at": grant.expires_at}


@router.post("/support-requests/{request_id}/reject", status_code=204)
async def reject_support_request(request: Request, request_id: str):
    request_store = pending_support_request_store(request.app.state)
    pending = await request_store.get(request_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="No such request, or it has expired")
    if not await request_store.mark_rejected(request_id):
        raise HTTPException(status_code=409, detail="This request was already decided, or has expired")
    audit_request(
        request,
        "support_grant.reject",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=pending.provider_subject,
        request_id=request_id,
    )


@router.get("/support-grants")
async def list_active_support_grants(request: Request):
    """ "Who can reach my stack right now" — the control ADR-0017 gives the tenant."""
    grants = await support_grant_store(request.app.state).list_active()
    return {
        "grants": [
            {
                "id": g.id,
                "provider_subject": g.provider_subject,
                "scopes": sorted(g.scopes),
                "issued_at": g.issued_at,
                "expires_at": g.expires_at,
                "step_up_verified": g.step_up_verified,
                "self_issued": g.self_issued,
            }
            for g in grants
        ]
    }


@router.delete("/support-grants/{grant_id}", status_code=204)
async def revoke_support_grant(request: Request, grant_id: str):
    result = await support_grant_store(request.app.state).revoke(grant_id)
    if not result.ok and result.reason == "not_found":
        raise HTTPException(status_code=404, detail="No such grant")
    # "revoked" (already revoked) and "expired" both report the same 204 here — idempotent by
    # design (§8): a tenant admin clicking revoke twice, or on something that lapsed on its
    # own between page load and click, must see the same success either way. Only an actual
    # revoke transition gets its own audit record — an idempotent no-op has no new fact to
    # record, the same reasoning `GET .../plans/{id}`'s plain 404 gets no bespoke audit event.
    if result.ok:
        # ADR-0017 §8: reach for anything still running under this grant on THIS process
        # (see support_grant_inflight.py — a call on a different replica still stops, just
        # via its own existing timeout rather than immediately). Recorded on the audit event
        # rather than in the response body so this route's 204-no-content contract is
        # unchanged; the count is what "the console must say so" resolves to for now.
        interrupted = support_grant_inflight_registry(request.app.state).cancel_all(grant_id)
        audit_request(
            request,
            "support_grant.revoke",
            outcome=AUDIT_OUTCOME_SUCCESS,
            target=result.grant.provider_subject if result.grant is not None else grant_id,
            grant_id=grant_id,
            interrupted_calls=interrupted,
        )
