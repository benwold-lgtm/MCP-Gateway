# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for worker-fleet liveness signals (SRE #7/#8).

#7 — the gateway counts only workers with a live heartbeat, so a degraded fleet
     (crashed workers still in workers:active) is reported accurately.
#8 — the worker heartbeat is withheld when a critical loop has crashed or the
     assignment consumer has stalled, and dead workers are pruned from the set.
"""

import asyncio
import time

import pytest
import fakeredis.aioredis

from device_mcp_gateway.main import _count_live_workers
from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30}}


def _shared_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _worker(worker_id, redis):
    return DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)


# --- #7: gateway counts live workers ----------------------------------------


@pytest.mark.asyncio
async def test_count_live_workers_gates_on_heartbeat():
    r = _shared_redis()
    await r.sadd("workers:active", "w1", "w2", "w3")
    await r.set("worker:w1:heartbeat", "t", ex=60)
    await r.set("worker:w2:heartbeat", "t", ex=60)
    # w3 is in the set but has no heartbeat (crashed without deregistering).
    assert await _count_live_workers(r) == 2


@pytest.mark.asyncio
async def test_count_live_workers_zero_when_none_registered():
    assert await _count_live_workers(_shared_redis()) == 0


# --- #8: heartbeat reflects loop health -------------------------------------


@pytest.mark.asyncio
async def test_loops_healthy_when_running():
    worker = _worker("w", _shared_redis())
    worker._critical_tasks = []
    worker._assignment_progress = time.monotonic()
    assert worker._loops_healthy() is True


@pytest.mark.asyncio
async def test_loops_unhealthy_when_critical_task_crashed():
    worker = _worker("w", _shared_redis())

    async def _exits():
        return  # simulates a critical loop that exited

    t = asyncio.create_task(_exits())
    await t
    worker._critical_tasks = [t]
    worker._assignment_progress = time.monotonic()
    assert worker._loops_healthy() is False


@pytest.mark.asyncio
async def test_loops_unhealthy_when_assignment_consumer_stalled():
    worker = _worker("w", _shared_redis())
    worker._critical_tasks = []
    worker._liveness_staleness = 5
    worker._assignment_progress = time.monotonic() - 100  # stalled
    assert worker._loops_healthy() is False


@pytest.mark.asyncio
async def test_loops_healthy_while_shutting_down():
    """A stalled timestamp during shutdown is not a liveness failure."""
    worker = _worker("w", _shared_redis())
    worker._stop_event.set()
    worker._assignment_progress = time.monotonic() - 1000
    assert worker._loops_healthy() is True


# --- #8: dead-worker pruning ------------------------------------------------


@pytest.mark.asyncio
async def test_prune_dead_workers_removes_those_without_heartbeat():
    r = _shared_redis()
    worker = _worker("leader", r)
    await r.sadd("workers:active", "live", "dead")
    await r.set("worker:live:heartbeat", "t", ex=60)

    await worker._prune_dead_workers()

    members = await r.smembers("workers:active")
    assert "live" in members
    assert "dead" not in members
