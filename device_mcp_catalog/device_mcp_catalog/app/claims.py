# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Claim recording (ADR-0020 §4, slice 4).

The claim itself — merging a device type's template with a tenant-supplied host and
registering the device — happens entirely in the console BFF, against the gateway's
existing `POST /devices` route (this service is never in that call path). This route is
the one thing that DOES belong here: pinning down which curated version a now-registered
device came from, so slice 5's upgrade-offer diff has a baseline to compare against.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import require_api_token
from .repo import ClaimRepo, DeviceTypeVersionNotFound
from .schemas import Claim, RecordClaim

router = APIRouter(dependencies=[Depends(require_api_token)])


@router.post("/device-types/{type_id}/claims", response_model=Claim, status_code=201)
async def record_claim(type_id: uuid.UUID, body: RecordClaim, request: Request):
    repo = ClaimRepo(request.app.state.db)
    try:
        return await repo.record_claim(type_id, body.version, body.tenant_id, body.hostname)
    except DeviceTypeVersionNotFound:
        raise HTTPException(status_code=404, detail=f"no curated version {body.version} of device type '{type_id}'")
