# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for worker load rebalancing on scale-out (F-07).

Each worker sheds devices above the per-worker target (ceil(total / live workers))
and declines new assignments while at/over target, so a scaled-out/idle worker
actually picks up load instead of early workers staying hot.
"""

import fakeredis.aioredis
import pytest

from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30, "reconcile_interval": 30}}


def _redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _worker(worker_id, redis):
    w = DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)
    w._backend = RedisRegistryBackend(redis)
    return w


async def _add_live_workers(redis, *ids):
    for wid in ids:
        await redis.sadd("workers:active", wid)
        await redis.set(f"worker:{wid}:heartbeat", "t", ex=60)


async def _add_devices(redis, *names):
    for n in names:
        await redis.sadd("devices:all", n)


class _StubPod:
    def stop(self):
        pass

    async def aclose(self):
        pass


async def _own(worker, *names):
    """Make ``worker`` the live owner of devices (claim + assigned + stub pod)."""
    for n in names:
        await worker._r.set(f"claim:{n}", worker._id)
        await worker._r.sadd(f"worker:{worker._id}:devices", n)
        worker._assigned.add(n)
        worker._pods[n] = _StubPod()


# --- target math -------------------------------------------------------------


@pytest.mark.asyncio
async def test_rebalance_target_is_ceil_total_over_live():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1", "w2", "w3")
    await _add_devices(r, "a", "b", "c", "d", "e", "f", "g")  # 7 devices / 3 workers
    target, live = await w._rebalance_target()
    assert live == 3 and target == 3  # ceil(7/3)


# --- decline rule ------------------------------------------------------------


@pytest.mark.asyncio
async def test_declines_when_at_or_over_target_with_peers():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1", "w2")
    await _add_devices(r, "a", "b", "c", "d")  # target = ceil(4/2) = 2
    await _own(w, "a", "b")  # already at target
    assert await w._decline_assignment("c") is True


@pytest.mark.asyncio
async def test_accepts_when_under_target():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1", "w2")
    await _add_devices(r, "a", "b", "c", "d")  # target = 2
    await _own(w, "a")  # under target
    assert await w._decline_assignment("c") is False


@pytest.mark.asyncio
async def test_single_worker_never_declines():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1")
    await _add_devices(r, "a", "b", "c")  # target = 3, but live == 1
    await _own(w, "a", "b", "c")
    assert await w._decline_assignment("d") is False


@pytest.mark.asyncio
async def test_declines_own_cooldown_device():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1", "w2")
    await _add_devices(r, "a")
    await r.set("rebalance:cooldown:a", "w1")  # we just shed it
    assert await w._decline_assignment("a") is True
    await r.set("rebalance:cooldown:a", "w2")  # someone else's cooldown — not ours
    assert await w._decline_assignment("a") is False  # under target, accept


# --- shedding ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_rebalance_once_sheds_down_to_target():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1", "w2")
    await _add_devices(r, "a", "b", "c", "d")  # target = ceil(4/2) = 2
    await _own(w, "a", "b", "c", "d")  # this worker hogs all 4

    await w._rebalance_once()

    assert len(w._assigned) == 2  # shed down to target
    # The two shed devices were released and re-published as assignments...
    assignments = await r.xrange("device:assignments")
    shed = {fields["hostname"] for _id, fields in assignments if fields.get("action") == "assign"}
    assert len(shed) == 2
    for h in shed:
        assert await r.get(f"claim:{h}") is None  # claim released
        assert await r.get(f"rebalance:cooldown:{h}") == "w1"  # cooldown marks it ours


@pytest.mark.asyncio
async def test_rebalance_once_noop_when_at_target():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1", "w2")
    await _add_devices(r, "a", "b", "c", "d")  # target = 2
    await _own(w, "a", "b")  # exactly at target
    await w._rebalance_once()
    assert len(w._assigned) == 2  # nothing shed


@pytest.mark.asyncio
async def test_rebalance_single_worker_noop():
    r = _redis()
    w = _worker("w1", r)
    await _add_live_workers(r, "w1")
    await _add_devices(r, "a", "b", "c")
    await _own(w, "a", "b", "c")
    await w._rebalance_once()
    assert len(w._assigned) == 3  # only one worker — nowhere to shed


@pytest.mark.asyncio
async def test_rebalance_disabled_is_noop():
    r = _redis()
    cfg = {"registry": {"health_check_interval": 30, "rebalance_enabled": False}}
    w = DeviceWorker(worker_id="w1", config=cfg, redis_client=r)
    w._backend = RedisRegistryBackend(r)
    await _add_live_workers(r, "w1", "w2")
    await _add_devices(r, "a", "b", "c", "d")
    await _own(w, "a", "b", "c", "d")
    # The loop guard skips when disabled; the decline rule is also off.
    assert await w._decline_assignment("x") is False
