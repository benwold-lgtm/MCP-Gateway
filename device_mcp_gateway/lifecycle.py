# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Background lifecycle tasks and liveness signals shared by the app factory and probes.

These ran inline in ``main.py`` before the router split; they live here so the
probe routes (``api/probes.py``) and the lifespan (``main.create_app``) can share
them without a circular import. ``main`` re-exports the test-touched names.
"""

from __future__ import annotations

import asyncio
import time
import uuid

from fastapi import FastAPI
from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.core.backoff import jittered

_LOOP_HEARTBEAT_INTERVAL = 1.0  # seconds between event-loop liveness ticks

_GAUGE_LEADER_LOCK = "gateway:gauge-leader"


async def _event_loop_heartbeat(app: FastAPI) -> None:
    """Stamp a monotonic tick every second so /livez can prove the loop is turning.

    A liveness probe against /health does real Redis work, so it answers readiness,
    not liveness, and a gateway whose event loop is wedged by a long blocking call
    can keep *serving* cached responses while the data path stalls (F-17). This tiny
    task can only advance the tick if the loop is actually scheduling coroutines;
    when the loop is wedged the tick goes stale and /livez flips to 503 — a true
    "wedged-but-serving" signal — with no I/O of its own.
    """
    while True:
        app.state.loop_heartbeat = time.monotonic()
        await asyncio.sleep(_LOOP_HEARTBEAT_INTERVAL)


async def _count_live_workers(redis) -> int:
    """Count workers with a live heartbeat (distributed mode).

    `workers:active` can retain ids of crashed workers that never deregistered, so
    membership alone overstates the fleet — gate on the heartbeat key, which the
    worker refreshes and which expires on death. Used as a degraded signal in
    /health (SRE #7): a gateway with zero live workers still serves read endpoints,
    but tool calls will time out, and operators/UI should see that.
    """
    ids = await redis.smembers("workers:active")
    if not ids:
        return 0
    pipe = redis.pipeline()
    for wid in ids:
        pipe.exists(f"worker:{wid}:heartbeat")
    return sum(1 for present in await pipe.execute() if present)


async def _acquire_gauge_leadership(redis, leader_id: str, ttl: int) -> bool:
    """Claim/refresh the gauge-refresh leader lock (SRE O4).

    SET NX to take it; if we already hold it, refresh the TTL so leadership is
    sticky while this replica is alive but lapses soon after it dies, letting
    another replica take over. Mirrors the worker reconciler's election.
    """
    if await redis.set(_GAUGE_LEADER_LOCK, leader_id, nx=True, ex=ttl):
        return True
    if (await redis.get(_GAUGE_LEADER_LOCK)) == leader_id:
        await redis.expire(_GAUGE_LEADER_LOCK, ttl)
        return True
    return False


async def _refresh_device_gauges(app: FastAPI, interval: float) -> None:
    """Periodically refresh device-fleet gauges from the registry.

    Prometheus collection is synchronous, but ``list_devices()`` is async, so we
    cannot compute these inside a collector — we poll on a timer instead.

    Leader-gated (SRE O4): in distributed mode every gateway replica runs this
    loop, so without gating each would do a full ``list_devices()`` every cycle
    (×replicas Redis load). Only the lock holder computes the fleet gauges; the
    others idle and stand ready to take over if the leader dies. Consequence: the
    fleet gauges are populated on one replica at a time, so aggregate them with
    ``max()`` across replicas in Prometheus. Embedded mode (no Redis) is a single
    process, so it always refreshes.
    """
    redis = getattr(app.state, "redis", None)
    leader_id = uuid.uuid4().hex
    lock_ttl = max(int(interval * 2), 30)
    while True:
        try:
            reg = app.state.registry
            is_leader = redis is None or await _acquire_gauge_leadership(redis, leader_id, lock_ttl)
            # Export leadership so an alert fires when no replica holds it — the
            # gauge-refresh election is a coordination SPOF (F-21). Only meaningful
            # in distributed mode (multiple replicas contend); embedded has no Redis.
            if redis is not None:
                metrics.gauge_leader.set(1 if is_leader else 0)
            if reg is not None and is_leader:
                devices = await reg.list_devices()
                metrics.registered_devices.set(len(devices))
                metrics.active_pods.set(sum(1 for d in devices if d.pod_active))
                metrics.reachable_devices.set(sum(1 for d in devices if d.reachable))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("device gauge refresh failed")
        await asyncio.sleep(jittered(interval))  # F-61: de-sync leader-election/refresh across replicas
