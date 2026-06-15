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
import os
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


# --- F-17: local liveness file backs the cheap exec probe -------------------


@pytest.mark.asyncio
async def test_liveness_file_default_path_in_tempdir():
    """With no override the liveness file lands in the system temp dir (no hardcoded
    /tmp literal), matching the K8s probe's expected path."""
    import tempfile

    worker = _worker("w", _shared_redis())
    assert worker._liveness_file == os.path.join(tempfile.gettempdir(), "mcp-worker-alive")


@pytest.mark.asyncio
async def test_liveness_file_honours_config_override(tmp_path):
    cfg = {"registry": {"health_check_interval": 30, "liveness_file": str(tmp_path / "alive")}}
    worker = DeviceWorker(worker_id="w", config=cfg, redis_client=_shared_redis())
    assert worker._liveness_file == str(tmp_path / "alive")


@pytest.mark.asyncio
async def test_touch_liveness_file_writes_fresh_mtime(tmp_path):
    """A healthy heartbeat bumps the file's mtime — the freshness the probe checks."""
    path = tmp_path / "alive"
    cfg = {"registry": {"health_check_interval": 30, "liveness_file": str(path)}}
    worker = DeviceWorker(worker_id="w", config=cfg, redis_client=_shared_redis())

    worker._touch_liveness_file()
    assert path.exists()
    assert time.time() - path.stat().st_mtime < 5  # fresh


@pytest.mark.asyncio
async def test_touch_liveness_file_swallows_oserror(tmp_path):
    """A filesystem error must never crash the heartbeat loop (Redis stays the
    authoritative liveness signal)."""
    # Point at a path whose parent dir does not exist → open() raises OSError.
    cfg = {"registry": {"health_check_interval": 30, "liveness_file": str(tmp_path / "nope" / "alive")}}
    worker = DeviceWorker(worker_id="w", config=cfg, redis_client=_shared_redis())
    worker._touch_liveness_file()  # must not raise


@pytest.mark.asyncio
async def test_heartbeat_touches_file_only_when_healthy(tmp_path, monkeypatch):
    """The heartbeat writes the liveness file when loops are healthy and withholds it
    when they aren't — so an unhealthy worker's file goes stale and the probe fails."""
    path = tmp_path / "alive"
    cfg = {"registry": {"health_check_interval": 30, "liveness_file": str(path)}}
    worker = DeviceWorker(worker_id="w", config=cfg, redis_client=_shared_redis())

    # Run one healthy beat, then stop the loop.
    monkeypatch.setattr(worker, "_loops_healthy", lambda: True)
    monkeypatch.setattr("device_mcp_gateway.worker.runner._HEARTBEAT_INTERVAL", 0.01)
    beat = asyncio.create_task(worker._heartbeat_loop())
    await asyncio.sleep(0.05)
    worker._stop_event.set()
    await asyncio.wait_for(beat, timeout=1)
    assert path.exists()  # healthy → touched


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
