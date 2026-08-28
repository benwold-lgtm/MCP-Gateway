# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Assignment routes (ADR-0020 §2, slice 2).

Assignment is an offer: it makes a device type appear in a tenant's console as available to
claim. It writes to this service's own storage only — there is no code path from here into
any tenant's registry. The tenant's own act of claiming (slice 4) is what actually registers
a device, in the tenant's own stack, by their own credential.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import Caller, enforce_tenant_scope, require_provider
from .repo import AssignmentNotFound, AssignmentRepo, DeviceTypeNotFound
from .schemas import AssignRequest, Assignment, TenantAssignmentsResponse

router = APIRouter(dependencies=[Depends(enforce_tenant_scope)])


def _repo(request: Request) -> AssignmentRepo:
    return AssignmentRepo(request.app.state.db)


@router.post("/device-types/{type_id}/assign", response_model=Assignment, status_code=201)
async def assign_device_type(
    type_id: uuid.UUID, body: AssignRequest, request: Request, _: Caller = Depends(require_provider)
):
    """Provider-only. Note this route names a tenant in its body and is still gated on the
    provider class: a tenant assigning a device type to itself would be granting itself an
    offer, which is the provider's half of §2 and not a scoping question."""
    try:
        return await _repo(request).assign(type_id, body.tenant_id, body.assigned_by)
    except DeviceTypeNotFound:
        raise HTTPException(status_code=404, detail=f"no device type '{type_id}'")


@router.delete("/device-types/{type_id}/assign/{tenant_id}", status_code=204)
async def revoke_assignment(
    type_id: uuid.UUID, tenant_id: str, request: Request, _: Caller = Depends(require_provider)
):
    try:
        await _repo(request).revoke(type_id, tenant_id)
    except AssignmentNotFound:
        raise HTTPException(status_code=404, detail=f"no active assignment of '{type_id}' to tenant '{tenant_id}'")


@router.get("/tenants/{tenant_id}/assignments", response_model=TenantAssignmentsResponse)
async def list_tenant_assignments(tenant_id: str, request: Request):
    """Both caller classes. `tenant_id` is still a path parameter — a client assertion — and
    `enforce_tenant_scope` has already refused the request if a tenant caller named anyone but
    itself, so by the time this body runs the two agree. The parameter is not the authority;
    the credential is."""
    return TenantAssignmentsResponse(device_types=await _repo(request).list_for_tenant(tenant_id))
