# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Upgrade offers (ADR-0020 §4, slice 5).

Never blocking, never scheduled, never forced (§4's resolved open question) — this route
only reports the diff between what a claimed device is pinned to and what is currently
curated. Accepting an offer is the tenant re-claiming at the new version (the existing
`POST /device-types/{id}/claims` route, called again with the new version); there is no
separate "apply" endpoint here, and nothing on this path ever touches the gateway or a live
device.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from .auth import require_api_token
from .repo import ClaimRepo
from .schemas import UpgradeOffersResponse

router = APIRouter(dependencies=[Depends(require_api_token)])


@router.get("/tenants/{tenant_id}/upgrades", response_model=UpgradeOffersResponse)
async def list_upgrade_offers(tenant_id: str, request: Request):
    repo = ClaimRepo(request.app.state.db)
    return UpgradeOffersResponse(offers=await repo.list_upgrade_offers(tenant_id))
