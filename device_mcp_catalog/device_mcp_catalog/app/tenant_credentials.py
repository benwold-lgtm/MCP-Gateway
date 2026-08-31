# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Issue and revoke a tenant's catalog credential (ADR-0024 §10, ADR-0020 §7a).

§7a established that each tenant console holds its own catalog credential rather than sharing
the provider's, and shipped that as a static env map because nothing could mint one.
§10 supplies the lifecycle: **approving an enrolment is the moment a tenant first needs catalog
access, and the moment both sides' identities are known.** These routes are what an enrolment
calls.

**Provider-only, all of them.** Issuing a tenant's credential is the provider's act — it is the
provider's catalog, and the credential is one of its own caller table's entries. A tenant
console minting its own would be the estate's authorization model asking the applicant to fill
in their own pass.

The plaintext credential is returned exactly once, from the issue call, and stored only as a
hash. There is deliberately no route that re-shows one: a store that can re-show a credential
is a store that can leak one, and the recovery path is to issue another and revoke the old.
"""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import Caller, hash_credential, require_provider
from .crypto import codec_for
from .repo import TenantCredentialRepo, TenantRegistryRepo
from .schemas import IssuedCredential, TenantCredential, TenantCredentialListResponse

router = APIRouter()

#: Prefix on an issued catalog credential. Purely diagnostic — unlike the gateway's `enr_`/
#: `inv_` prefixes it gates nothing, because this service resolves a credential by hashing it
#: and looking it up rather than by shape. It exists so that a credential found in a config
#: file or a log is identifiable as a catalog token rather than an anonymous secret.
CREDENTIAL_PREFIX = "cat_"


def _repo(request: Request) -> TenantCredentialRepo:
    return TenantCredentialRepo(request.app.state.db)


@router.post("/tenants/{tenant_id}/credentials", status_code=201, response_model=IssuedCredential)
async def issue_credential(tenant_id: str, request: Request, caller: Caller = Depends(require_provider)):
    """Mint a credential for one tenant. The plaintext is in this response and nowhere else.

    Note this route names a tenant in its path and is still provider-only, which is not a
    contradiction of §7a's "the tenant is read from the credential": that rule constrains a
    *tenant* caller to its own tenant. A provider naming a tenant here is the provider acting
    on its own caller table, which is exactly the authority §7a's table gives it.
    """
    body = await request.json() if await request.body() else {}
    label = str(body.get("label", "")).strip()

    credential = CREDENTIAL_PREFIX + secrets.token_urlsafe(32)
    credential_id = await _repo(request).issue(
        tenant_id,
        credential_hash=hash_credential(credential),
        label=label,
        # Attested by the caller's own credential rather than taken from the body, the rule
        # `assigned_by` and ADR-0017's `provider_subject` already follow everywhere it matters.
        issued_by=caller.kind,
    )
    return IssuedCredential(
        id=credential_id,
        tenant_id=tenant_id,
        label=label,
        credential=credential,
    )


@router.get("/tenants/{tenant_id}/credentials", response_model=TenantCredentialListResponse)
async def list_credentials(
    tenant_id: str, request: Request, include_revoked: bool = False, _: Caller = Depends(require_provider)
):
    """What this tenant holds. Carries no hashes and no secrets — see the module docstring."""
    rows = await _repo(request).list_for_tenant(tenant_id, include_revoked=include_revoked)
    return TenantCredentialListResponse(credentials=[TenantCredential(**row) for row in rows])


@router.delete("/tenants/{tenant_id}/credentials/{credential_id}", status_code=204)
async def revoke_credential(
    tenant_id: str, credential_id: uuid.UUID, request: Request, _: Caller = Depends(require_provider)
):
    """Revoke one credential. Takes effect on that tenant's very next catalog request, because
    `auth.py` resolves an issued credential live rather than from anything cached."""
    if not await _repo(request).revoke(credential_id):
        raise HTTPException(status_code=404, detail=f"no credential '{credential_id}'")


@router.delete("/tenants/{tenant_id}/credentials", status_code=200)
async def revoke_all_credentials(tenant_id: str, request: Request, _: Caller = Depends(require_provider)):
    """End every live credential this tenant holds — what revoking an enrolment calls.

    §10: "revoking an enrolment revokes that credential too." One call rather than a client
    loop, so ending a relationship cannot half-happen because something interrupted the caller
    between two revokes. Returns a count rather than 204 so the caller can record how many
    were actually live, which is the difference between "revoked" and "already gone".
    """
    return {"revoked": await _repo(request).revoke_all_for_tenant(tenant_id)}


@router.post("/tenants", status_code=201)
async def enrol_tenant(request: Request, caller: Caller = Depends(require_provider)):
    """Record a tenant AND issue its catalog credential, in one transaction (ADR-0024 §11).

    This replaces two separate calls — `POST /tenants/{id}/credentials` followed by an operator
    editing `PROVIDER_TENANT_REGISTRY` — with one that cannot half-happen. The older credential
    route stays for the bootstrap case (issuing a second credential to a tenant already enrolled,
    or to one that predates enrolment); this is the path the enrolment handshake uses.
    """
    body = await request.json() if await request.body() else {}
    tenant_id = str(body.get("tenant_id", "")).strip()
    gateway_url = str(body.get("gateway_url", "")).strip()
    if not tenant_id or not gateway_url:
        raise HTTPException(status_code=400, detail="tenant_id and gateway_url are required")

    credential = CREDENTIAL_PREFIX + secrets.token_urlsafe(32)
    repo = TenantRegistryRepo(request.app.state.db, codec=codec_for(request.app.state))
    credential_id = await repo.enrol(
        tenant_id,
        display_name=str(body.get("display_name", "")).strip() or tenant_id,
        gateway_url=gateway_url,
        gateway_credential=str(body.get("gateway_credential", "")).strip(),
        enrolment_id=str(body.get("enrolment_id", "")).strip(),
        enrolled_by=caller.kind,
        credential_hash=hash_credential(credential),
        credential_label=str(body.get("label", "")).strip() or "enrolment",
    )
    return {"tenant_id": tenant_id, "credential_id": credential_id, "credential": credential}


@router.get("/tenants")
async def list_tenants(request: Request, _: Caller = Depends(require_provider)):
    """The estate. Carries no credentials — see `gateway-credential` below."""
    repo = TenantRegistryRepo(request.app.state.db)
    return {"tenants": await repo.list_tenants()}


@router.get("/tenants/{tenant_id}/gateway-credential")
async def tenant_gateway_credential(tenant_id: str, request: Request, _: Caller = Depends(require_provider)):
    """The provider's own credential for one tenant's gateway, decrypted.

    404 rather than an empty object for an unknown tenant: "not enrolled" and "enrolled with
    nothing recorded" are different conditions, and a console that could not tell them apart
    would show the same empty state for both.
    """
    repo = TenantRegistryRepo(request.app.state.db, codec=codec_for(request.app.state))
    found = await repo.gateway_credential(tenant_id)
    if found is None:
        raise HTTPException(status_code=404, detail=f"tenant '{tenant_id}' is not enrolled")
    return found


@router.put("/tenants/{tenant_id}/gateway-credential", status_code=200)
async def set_tenant_gateway_credential(tenant_id: str, request: Request, _: Caller = Depends(require_provider)):
    """Fill in the provider's own credential for a tenant's gateway, once the handshake has one.

    Separate from `POST /tenants` because the enrolment ordering leaves no choice: the tenant's
    catalog credential must exist before the redemption (the redemption is what hands it over)
    and the provider's credential only exists after it. Making this a second call is honest
    about that; folding it into the enrol transaction would mean claiming an atomicity the
    plane boundary does not allow, which is the over-reach §11 exists to avoid.

    Not `POST /tenants` again: that would mint a *second* catalog credential for a tenant that
    already has a live one, which is how caller tables acquire entries nobody can account for.
    """
    body = await request.json() if await request.body() else {}
    credential = str(body.get("gateway_credential", "")).strip()
    if not credential:
        raise HTTPException(status_code=400, detail="gateway_credential is required")

    repo = TenantRegistryRepo(request.app.state.db, codec=codec_for(request.app.state))
    recorded = await repo.set_gateway_credential(
        tenant_id,
        gateway_credential=credential,
        enrolment_id=str(body.get("enrolment_id", "")).strip(),
    )
    if not recorded:
        raise HTTPException(status_code=404, detail=f"tenant '{tenant_id}' is not enrolled")
    return {"tenant_id": tenant_id, "recorded": True}


@router.delete("/tenants/{tenant_id}", status_code=200)
async def withdraw_tenant(tenant_id: str, request: Request, _: Caller = Depends(require_provider)):
    """End the relationship: remove the registry entry and revoke every live credential, in one
    transaction — §11's property to test, with no operator step in between."""
    repo = TenantRegistryRepo(request.app.state.db)
    return await repo.withdraw(tenant_id)
