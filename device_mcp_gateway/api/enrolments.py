# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Issue / redeem / list / revoke enrolments (ADR-0024 §10).

**Two routers, and the split is the point.** Everything a tenant administrator does is gated by
`support:administer` and lives on the protected router like every other management route.
Redemption is not, because it cannot be: a provider redeeming an invitation holds no gateway
credential yet — acquiring one is what redemption is *for*.

That does not make redemption unauthenticated. §10 rejects an unauthenticated enrolment
endpoint for the reason ADR-0017 §7a rejected an unauthenticated raise route: it converts a
closed surface on the tenant's gateway into an open one, and that trade belongs to the tenant
rather than to a default. What authenticates redemption is **the invitation itself** — a
one-time, short-lived credential the tenant generated and handed over deliberately. The route
is outside the RBAC machinery, not outside authentication.

The invitation code is deliberately NOT resolvable by `CompositeAuthenticator`, unlike the
`enr_` credential redemption produces. If an invitation could authenticate an ordinary request,
a bootstrap secret handed over in an email would be standing access to the tenant's gateway —
the codes are separated by prefix (`inv_` vs `enr_`) so that confusing the two is not something
a future route can do by accident.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.cfg import configured_tenant_id
from device_mcp_gateway.enrolments import (
    DEFAULT_INVITATION_TTL_SECONDS,
    INVITATION_CODE_PREFIX,
    enrolment_store,
    invitation_store,
)
from device_mcp_gateway.rbac import SCOPE_SUPPORT_ADMINISTER, require_scope

_ADMINISTER = Depends(require_scope(SCOPE_SUPPORT_ADMINISTER))

#: The tenant-administrator half. Same scope as the support-request inbox, deliberately: both
#: are "administering this tenant's relationship with its provider", and a tenant admin who can
#: approve a support request but not see who is enrolled would be holding half a control.
router = APIRouter()

#: The redemption half, mounted OUTSIDE `authenticate_request` — see the module docstring.
redeem_router = APIRouter()


def _principal_subject(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "subject", "unknown")


@router.post("/enrolment-invitations", status_code=201, dependencies=[_ADMINISTER])
async def create_invitation(request: Request):
    """Mint an invitation for a provider, to be handed over out of band.

    The plaintext code is in this response and **nowhere else** — the store keeps only its
    hash. An admin who loses it issues another; there is no recovery route, because a store
    that can re-show a credential is a store that can leak one.
    """
    body = await request.json() if await request.body() else {}
    provider_label = str(body.get("provider_label", "")).strip()
    if not provider_label:
        raise HTTPException(
            status_code=400,
            detail="provider_label is required — an invitation nobody can attribute is one nobody can safely hand over",
        )
    ttl = int(body.get("ttl_seconds", DEFAULT_INVITATION_TTL_SECONDS))

    store = invitation_store(request.app.state)
    code, invitation = await store.create(
        created_by=_principal_subject(request), provider_label=provider_label, ttl_seconds=ttl
    )
    audit_request(
        request,
        "enrolment.invitation.created",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=provider_label,
    )
    return {
        "code": code,
        "provider_label": invitation.provider_label,
        "expires_at": invitation.expires_at,
        "created_by": invitation.created_by,
    }


@router.get("/enrolment-invitations", dependencies=[_ADMINISTER])
async def list_invitations(request: Request):
    """Outstanding invitations — what has been handed out and not yet redeemed."""
    store = invitation_store(request.app.state)
    return {
        "invitations": [
            {
                "code_hash": i.code_hash,
                "provider_label": i.provider_label,
                "created_by": i.created_by,
                "created_at": i.created_at,
                "expires_at": i.expires_at,
            }
            for i in await store.list_live()
        ]
    }


@router.delete("/enrolment-invitations/{code_hash}", status_code=204, dependencies=[_ADMINISTER])
async def revoke_invitation(code_hash: str, request: Request):
    """Withdraw an invitation before it is redeemed — a handover that went to the wrong place
    should be endable without waiting out its TTL."""
    store = invitation_store(request.app.state)
    existed = await store.revoke(code_hash)
    audit_request(
        request,
        "enrolment.invitation.revoked",
        outcome=AUDIT_OUTCOME_SUCCESS if existed else AUDIT_OUTCOME_DENIED,
        target=code_hash,
    )
    if not existed:
        raise HTTPException(status_code=404, detail="no such invitation")


@router.get("/enrolments", dependencies=[_ADMINISTER])
async def list_enrolments(request: Request):
    """Every live relationship, with who approved it and when — §10's replacement for expiry.

    `last_used_at` is sourced from real authenticated requests rather than self-reported, so a
    dormant supplier relationship is discoverable by looking. `None` means the provider has not
    used this enrolment since it was approved, which is the signal this listing exists for.
    """
    store = enrolment_store(request.app.state)
    return {
        "enrolments": [
            {
                "enrolment_id": e.enrolment_id,
                "provider_subject": e.provider_subject,
                "provider_label": e.provider_label,
                "approved_by": e.approved_by,
                "approved_at": e.approved_at,
                "catalog_url": e.catalog_url,
                "last_used_at": e.last_used_at,
            }
            for e in await store.list_all()
        ]
    }


@router.get("/enrolments/catalog-configuration", dependencies=[_ADMINISTER])
async def catalog_configuration(request: Request):
    """What this tenant's console needs to reach its provider's catalog — the address and
    **this tenant's own** credential for it (ADR-0020 §7a, minted by §10's redemption).

    The one route here that returns a usable secret, and it is deliberately its own route
    rather than a field on the enrolment listing: a listing is a screen an admin leaves open,
    and a credential should be fetched by the component that needs it, when it needs it, not
    rendered alongside "who approved this and when".

    Gated by `support:administer` — the same scope as the rest of this module. There is no
    weaker one to reach for: this credential *is* the tenant's catalog access, so anyone who
    could read it could read the tenant's catalog anyway.

    Returns 404 rather than an empty object when no live enrolment exists, because "this
    tenant is not enrolled" and "enrolled with nothing configured" are different conditions and
    a console that could not tell them apart would show an empty catalog for both — the
    named-condition discipline ADR-0020 §7 already requires of the catalog itself.
    """
    store = enrolment_store(request.app.state)
    live = await store.list_all()
    if not live:
        raise HTTPException(status_code=404, detail="this tenant has no live enrolment")
    # The newest wins if somehow several exist. Re-enrolling after a revoke is the ordinary way
    # to replace a relationship, so the most recent approval is the current answer.
    enrolment = live[-1]
    codec = getattr(request.app.state, "codec", None)
    credential = enrolment.catalog_credential_encrypted
    if codec is not None:
        credential = codec.decrypt(credential)
    return {
        "catalog_url": enrolment.catalog_url,
        "catalog_credential": credential,
        "enrolment_id": enrolment.enrolment_id,
    }


@router.delete("/enrolments/{enrolment_id}", status_code=204, dependencies=[_ADMINISTER])
async def revoke_enrolment(enrolment_id: str, request: Request):
    """End the relationship, immediately and without a counterparty.

    Idempotent, following ADR-0017 §8's reasoning about revoke versus expiry: a tenant admin
    ending a supplier relationship is very often doing so *because* something is wrong right
    now, and a button that errors on the second click is a button that fails when it matters.
    """
    store = enrolment_store(request.app.state)
    result = await store.revoke(enrolment_id)
    audit_request(
        request,
        "enrolment.revoked",
        outcome=AUDIT_OUTCOME_SUCCESS if result.ok else AUDIT_OUTCOME_DENIED,
        target=enrolment_id,
        reason=result.reason,
    )
    if not result.ok:
        raise HTTPException(status_code=404, detail="no such enrolment")


@redeem_router.post("/enrolments/redeem", status_code=201)
async def redeem_invitation(request: Request, authorization: str = Header(default="")):
    """Redeem an invitation, creating the enrolment and every credential it implies.

    Authenticated by the invitation code in `Authorization: Bearer inv_...`. Deliberately not
    through `authenticate_request`: the caller has no gateway credential yet, and obtaining one
    is the purpose of this call.

    The provider supplies, in one act, what the tenant's side of the connection needs — the
    catalog's address and **this tenant's own** credential for it (ADR-0020 §7a) — and receives
    what the provider's side needs: a standing credential carrying `support:request` and
    nothing else. That is §10's atomicity requirement: every piece of state the connection
    depends on is created here, so none of it remains a step a human does separately.
    """
    # A stack that cannot say which tenant it is cannot be enrolled. Refused rather than
    # answered with a null: the provider uses this value to check that the catalog credential
    # it minted was minted for the tenant it is actually enrolling, and an optional check is
    # one skipped by exactly the deployment that got it wrong (ADR-0020 §7b's lesson, arriving
    # a level up — at the relationship rather than the request).
    #
    # This is also the first thing in the gateway to READ `gateway.tenant_id`, whose own
    # config comment said plainly that nothing did. Failing here, loudly, naming the field, is
    # the shape ADR-0024 §10 singles out as the model: step 5 of its nine "fails loudly, at
    # startup, naming the missing field", and is "the one to imitate".
    tenant_id = configured_tenant_id(request.app.state.config)
    if not tenant_id:
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "ERR_TENANT_ID_NOT_CONFIGURED",
                "message": (
                    "this gateway has no gateway.tenant_id set, so it cannot tell a provider "
                    "which tenant it is enrolling. Set it (ADR-0019's opaque identifier) before "
                    "issuing an invitation — an enrolment whose tenant nobody can name is one "
                    "nobody can verify was delivered to the right place."
                ),
            },
        )

    scheme, _, code = authorization.partition(" ")
    if scheme.lower() != "bearer" or not code.startswith(INVITATION_CODE_PREFIX):
        # A cheap shape check, and NOT the thing that keeps other credentials out — removing it
        # refuses an `enr_` credential just the same, because redemption looks up the invitation
        # store and a standing credential was never in it. (Verified by mutation: deleting this
        # line broke no test, which is how it earned this comment rather than a stronger one.)
        # What it buys is refusing garbage without a hash and a store round-trip.
        #
        # Deliberately the same refusal as a wrong code below. An endpoint that distinguished
        # "malformed" from "not a real invitation" would let an unauthenticated caller probe
        # for the shape of a valid code.
        raise HTTPException(status_code=401, detail="a valid invitation is required to redeem")

    body = await request.json() if await request.body() else {}
    provider_subject = str(body.get("provider_subject", "")).strip()
    catalog_url = str(body.get("catalog_url", "")).strip()
    catalog_credential = str(body.get("catalog_credential", "")).strip()
    missing = [
        name
        for name, value in (
            ("provider_subject", provider_subject),
            ("catalog_url", catalog_url),
            ("catalog_credential", catalog_credential),
        )
        if not value
    ]
    if missing:
        # Named rather than a bare 400, and refused rather than defaulted: a redemption that
        # succeeded without a catalog credential would produce an enrolment that looks complete
        # and leaves the tenant's catalog silently unreachable — step 9 of §10's nine, which
        # fails quietly and reads as "the catalog is down" while it is healthy.
        raise HTTPException(status_code=400, detail=f"redemption requires: {', '.join(missing)}")

    store = enrolment_store(request.app.state)
    result = await store.redeem(
        code=code,
        provider_subject=provider_subject,
        catalog_url=catalog_url,
        catalog_credential=catalog_credential,
    )
    if not result.ok or result.enrolment is None or result.credential is None:
        audit_request(
            request,
            "enrolment.redeem",
            outcome=AUDIT_OUTCOME_DENIED,
            subject=provider_subject,
            reason=result.reason,
        )
        # One status for every failure reason, for the probing reason above. The audit record
        # carries the distinction; the response does not.
        raise HTTPException(status_code=401, detail="a valid invitation is required to redeem")

    audit_request(
        request,
        "enrolment.redeem",
        outcome=AUDIT_OUTCOME_SUCCESS,
        subject=provider_subject,
        target=result.enrolment.enrolment_id,
    )
    return {
        "enrolment_id": result.enrolment.enrolment_id,
        # Which tenant the provider has just enrolled, from this stack's OWN configuration —
        # never from anything the redeeming caller sent. It is what lets the provider confirm
        # the catalog credential it minted belongs to the tenant it actually reached.
        "tenant_id": tenant_id,
        "credential": result.credential,
        "approved_by": result.enrolment.approved_by,
        "approved_at": result.enrolment.approved_at,
    }
