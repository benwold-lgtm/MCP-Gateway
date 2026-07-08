# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Unauthenticated operational probes: /health, /livez, /readyz.

Mounted directly on the app (no /v1 prefix, no auth) — these are infra contracts
consumed by Kubernetes and monitoring, not application clients.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from device_mcp_gateway import __version__
from device_mcp_gateway.lifecycle import _LOOP_HEARTBEAT_INTERVAL, _count_live_workers
from device_mcp_gateway.ratelimit import rate_limit
from device_mcp_gateway.registry.server import Registry

router = APIRouter()


@router.get("/health", dependencies=[Depends(rate_limit("300/minute", "health"))])
async def health_check(request: Request):
    reg: Registry = request.app.state.registry
    mode = request.app.state.mode
    cfg = request.app.state.config

    devices = await reg.list_devices()
    active = sum(1 for d in devices if d.pod_active)

    payload = {
        "status": "healthy",
        "mode": mode,
        "active_pods": active,
        "registered_devices": len(devices),
        "version": cfg.get("server", {}).get("version", __version__),
    }

    # Distributed mode: expose worker-fleet liveness as a degraded signal (SRE
    # #7). Stays HTTP 200 (this is the liveness target — a worker outage must
    # not restart the gateway), but flips status to "degraded" with a count so
    # the UI/operators can see that tool calls have no workers to serve them.
    if mode == "distributed":
        redis = request.app.state.redis
        live_workers = await _count_live_workers(redis) if redis is not None else 0
        payload["live_workers"] = live_workers
        if live_workers == 0:
            payload["status"] = "degraded"

    return payload


@router.get("/livez", dependencies=[Depends(rate_limit("300/minute", "livez"))])
async def liveness_check(request: Request):
    """Lightweight liveness probe — proves the event loop is turning (F-17).

    Unlike /health (which does Redis/registry work and is really a readiness
    signal), this does no I/O: it only checks that the background heartbeat tick
    is fresh. A wedged event loop can't advance the tick (and can't run this
    handler either), so the probe fails — catching a "wedged-but-serving"
    gateway that /health, answering from cache, would miss. K8s livenessProbe
    target.
    """
    last = getattr(request.app.state, "loop_heartbeat", None)
    # Stale if the ticker hasn't run for several intervals — loop wedged/starved.
    staleness_budget = _LOOP_HEARTBEAT_INTERVAL * 5
    if last is None or (time.monotonic() - last) > staleness_budget:
        return JSONResponse(
            status_code=503,
            content={"status": "not alive", "reason": "event loop heartbeat stale"},
        )
    return {"status": "alive"}


@router.get("/readyz", dependencies=[Depends(rate_limit("300/minute", "readyz"))])
async def readiness_check(request: Request):
    """Deep readiness probe — checks backend infrastructure connectivity.
    K8s readiness probe target; returns 503 until the backend is reachable.
    Unlike /health, does NOT check business state (device count, pod_active).
    """
    mode = request.app.state.mode
    try:
        if mode == "distributed":
            redis = request.app.state.redis
            if redis is None:
                return JSONResponse(
                    status_code=503,
                    content={"status": "not ready", "mode": mode, "reason": "Redis not yet connected"},
                )
            await redis.ping()
        else:
            await request.app.state.store.health_check()
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "not ready", "mode": mode, "reason": str(exc)},
        )
    return {"status": "ready", "mode": mode}
