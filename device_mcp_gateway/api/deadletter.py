# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Dead-letter queue operations (F-10, distributed mode)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.rbac import SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, require_scope

router = APIRouter()


def _require_distributed(request: Request):
    """Return the Redis backend, or 400 in embedded mode (no DLQ in-process)."""
    if request.app.state.mode != "distributed":
        raise HTTPException(status_code=400, detail="Dead-letter queue is only available in distributed mode")
    return request.app.state.registry._backend


async def _optional_ids(request: Request) -> list[str] | None:
    """Parse an optional ``{"ids": [...]}`` JSON body; None when absent/empty."""
    try:
        data = await request.json()
    except Exception:
        return None
    if isinstance(data, dict):
        ids = data.get("ids")
        if isinstance(ids, list) and all(isinstance(i, str) for i in ids):
            return ids or None
    return None


@router.get("/devices/{hostname}/deadletter", dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))])
async def list_dead_letters(hostname: str, request: Request, limit: int = Query(50, ge=1, le=500)):
    """Inspect a device's dead-lettered tool calls (newest first) — F-10."""
    backend = _require_distributed(request)
    entries = await backend.dead_letter_list(hostname, count=limit)
    return {"hostname": hostname, "count": len(entries), "entries": entries}


@router.post("/devices/{hostname}/deadletter/replay", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
async def replay_dead_letters(hostname: str, request: Request, limit: int = Query(50, ge=1, le=500)):
    """Re-publish dead-lettered calls onto the device's call stream and remove
    them from the DLQ. Optional JSON body ``{"ids": [...]}`` replays specific
    entries; otherwise up to ``limit`` oldest are replayed (F-10)."""
    backend = _require_distributed(request)
    ids = await _optional_ids(request)
    replayed = await backend.dead_letter_replay(hostname, ids=ids, count=limit)
    audit_request(request, "device.deadletter.replay", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname, count=replayed)
    return {"hostname": hostname, "replayed": replayed}


@router.delete("/devices/{hostname}/deadletter", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
async def purge_dead_letters(hostname: str, request: Request):
    """Drain a device's DLQ. Optional JSON body ``{"ids": [...]}`` deletes
    specific entries; otherwise the whole queue is dropped (F-10)."""
    backend = _require_distributed(request)
    ids = await _optional_ids(request)
    removed = await backend.dead_letter_purge(hostname, ids=ids)
    audit_request(request, "device.deadletter.purge", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname, removed=removed)
    return {"hostname": hostname, "removed": removed}
