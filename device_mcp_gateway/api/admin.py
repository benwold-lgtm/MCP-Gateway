# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Read-aggregate and identity routes: /metrics/summary, /admin/overview, /auth/me."""

from __future__ import annotations

import hashlib
import json
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from device_mcp_gateway.rbac import SCOPE_DEVICES_READ, SCOPE_METRICS_READ, require_scope
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.schemas import DeviceSummary, OverviewResponse, WhoAmIResponse

router = APIRouter()


@router.get("/metrics/summary", dependencies=[Depends(require_scope(SCOPE_METRICS_READ))])
async def get_metrics_summary(request: Request):
    # Human-readable JSON snapshot on the API port (scope-gated to metrics:read).
    # Prometheus exposition is served separately on the dedicated metrics port —
    # see metrics.start_metrics_server.
    reg: Registry = request.app.state.registry
    mode = request.app.state.mode
    devices = await reg.list_devices()
    reachable_count = sum(1 for d in devices if d.reachable)

    metrics: dict = {
        "mode": mode,
        "active_pods": sum(1 for d in devices if d.pod_active),
        "reachable_devices": reachable_count,
        "unreachable_devices": len(devices) - reachable_count,
        "total_registered": len(devices),
    }

    if mode == "embedded":
        metrics["device_rate_limits"] = {d.hostname: {"rate_limit_rps": d.rate_limit_rps} for d in devices}

    return metrics


@router.get("/auth/me", response_model=WhoAmIResponse)
async def whoami(request: Request):
    # Any authenticated caller may read its own identity (no scope gate) — the BFF
    # uses this to gate UI views on the gateway's scopes, so the UI and gateway can't
    # drift (ADR-0007). authenticate_request has already resolved the Principal.
    principal = request.state.principal
    return WhoAmIResponse(
        subject=principal.subject,
        scopes=sorted(principal.scopes),
        auth_method=principal.auth_method,
    )


@router.get(
    "/admin/overview",
    response_model=OverviewResponse,
    dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
)
async def admin_overview(request: Request):
    # Single-call aggregate for the UI/BFF (F14): fleet counts + the device list
    # in one round-trip, so the dashboard's landing screen isn't N+1 requests.
    # Served from a short-TTL per-replica cache with an ETag (SRE O4) so a
    # polling dashboard doesn't hit Redis (list_devices) on every request and
    # can short-circuit with a 304 when nothing changed.
    read_cache_ttl: float = request.app.state.config.get("gateway", {}).get("read_cache_ttl", 5)
    cache = request.app.state.overview_cache
    now = time.monotonic()
    if cache["body"] is None or (now - cache["ts"]) >= read_cache_ttl:
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode
        devices = await reg.list_devices()
        reachable_count = sum(1 for d in devices if d.reachable)
        body = {
            "mode": mode,
            "counts": {
                "total": len(devices),
                "active_pods": sum(1 for d in devices if d.pod_active),
                "reachable": reachable_count,
                "unreachable": len(devices) - reachable_count,
            },
            "devices": [DeviceSummary.from_config(d).model_dump() for d in devices],
        }
        etag = '"' + hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16] + '"'
        cache.update(ts=now, etag=etag, body=body)

    etag = cache["etag"]
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return JSONResponse(
        content=cache["body"],
        headers={"ETag": etag, "Cache-Control": f"max-age={int(read_cache_ttl)}"},
    )
