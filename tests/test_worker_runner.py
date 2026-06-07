# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for DeviceWorker's distributed device-claim lease.

Regression coverage for S1 real-concern RC-6: spawning a pod must be guarded by
an atomic Redis claim, not just the per-worker in-memory _assigned set, so a
device can never be run by two workers at once.
"""

import pytest
import fakeredis.aioredis

from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30}}


def _worker(worker_id, redis):
    return DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)


def _shared_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.mark.asyncio
async def test_claim_blocks_second_worker():
    r = _shared_redis()
    a, b = _worker("A", r), _worker("B", r)

    assert await a._acquire_claim("dev1") is True
    # B sees A's claim and must not proceed.
    assert await b._acquire_claim("dev1") is False
    assert await r.get("claim:dev1") == "A"


@pytest.mark.asyncio
async def test_claim_is_idempotent_for_owner():
    r = _shared_redis()
    a = _worker("A", r)

    assert await a._acquire_claim("dev1") is True
    # Re-acquiring our own claim (pod replace / restart recovery) succeeds.
    assert await a._acquire_claim("dev1") is True


@pytest.mark.asyncio
async def test_release_only_by_owner():
    r = _shared_redis()
    a, b = _worker("A", r), _worker("B", r)

    await a._acquire_claim("dev1")
    # B must not be able to drop A's claim.
    await b._release_claim("dev1")
    assert await r.get("claim:dev1") == "A"
    # A releases its own claim, freeing the device.
    await a._release_claim("dev1")
    assert await r.get("claim:dev1") is None
    assert await b._acquire_claim("dev1") is True


@pytest.mark.asyncio
async def test_refresh_extends_lease():
    r = _shared_redis()
    a = _worker("A", r)
    # Simulate a claim that's close to expiring.
    await r.set("claim:dev1", "A", ex=5)
    a._assigned.add("dev1")

    await a._refresh_claims()

    ttl = await r.ttl("claim:dev1")
    assert ttl > 5  # lease extended toward claim_ttl
    assert ttl <= a._claim_ttl


@pytest.mark.asyncio
async def test_spawn_skips_when_claimed_by_other_worker():
    r = _shared_redis()
    a, b = _worker("A", r), _worker("B", r)

    # A owns the claim; B's spawn must bail out before touching its (unset)
    # backend, leaving no pod and no local assignment.
    await a._acquire_claim("dev1")
    await b._spawn_pod("dev1")

    assert "dev1" not in b._assigned
    assert "dev1" not in b._pods
    assert await r.get("claim:dev1") == "A"  # A's claim untouched
