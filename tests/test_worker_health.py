# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Tests for the distributed worker health loop's spec-poll throttling.

Regression coverage for S1 finding 3: spec polling used cfg.last_check (rewritten
every health cycle) as its throttle, so `now - last_check` was always small and
the spec poll never fired. The loop now keeps a dedicated per-device timestamp.
"""

import hashlib
import time

import pytest
import fakeredis.aioredis

from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend
from device_mcp_gateway.worker.health import WorkerHealthLoop

SPEC = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}}
SPEC_HASH = hashlib.sha256(str(SPEC).encode()).hexdigest()[:16]


async def _make_loop(monkeypatch):
    backend = MemoryRegistryBackend()
    # spec_hash matches SPEC so the "changed" branch (which would invoke the
    # translator/ProcessPoolExecutor) is never taken in these tests.
    await backend.set_device(
        "dev1",
        DeviceConfig(hostname="dev1", base_url="http://dev1", spec_url="http://dev1/openapi.json", spec_hash=SPEC_HASH),
    )
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    loop = WorkerHealthLoop(
        worker_id="w1",
        backend=backend,
        redis_client=redis,
        interval=30,
        spec_poll_interval=300,
    )

    fetch_calls = {"n": 0}

    async def _fake_reach(_url):
        return True

    async def _fake_fetch(_cfg):
        fetch_calls["n"] += 1
        return SPEC

    monkeypatch.setattr(loop, "_check_reachability", _fake_reach)
    monkeypatch.setattr(loop, "_fetch_spec", _fake_fetch)
    return loop, backend, fetch_calls


@pytest.mark.asyncio
async def test_first_sighting_defers_spec_poll(monkeypatch):
    loop, _backend, fetch_calls = await _make_loop(monkeypatch)

    await loop._check_device("dev1")

    # The spec was just fetched at spawn; the first health cycle must not re-poll.
    assert fetch_calls["n"] == 0
    assert "dev1" in loop._last_spec_check


@pytest.mark.asyncio
async def test_spec_poll_fires_after_interval_despite_fresh_last_check(monkeypatch):
    loop, backend, fetch_calls = await _make_loop(monkeypatch)

    # First cycle seeds the spec-poll timestamp without polling.
    await loop._check_device("dev1")
    assert fetch_calls["n"] == 0

    # Age the dedicated spec-poll timestamp past the poll interval...
    loop._last_spec_check["dev1"] = time.time() - 301
    # ...while last_check stays fresh, exactly the condition that used to wedge
    # the old guard (now - cfg.last_check was always < spec_poll_interval).
    cfg = await backend.get_device("dev1")
    cfg.last_check = time.time()

    await loop._check_device("dev1")
    assert fetch_calls["n"] == 1  # poll fired despite a fresh last_check


@pytest.mark.asyncio
async def test_spec_poll_throttled_within_interval(monkeypatch):
    loop, _backend, fetch_calls = await _make_loop(monkeypatch)

    await loop._check_device("dev1")  # seed
    loop._last_spec_check["dev1"] = time.time() - 301
    await loop._check_device("dev1")  # fires → n == 1
    await loop._check_device("dev1")  # immediately again → throttled

    assert fetch_calls["n"] == 1


# --- RC-1: health-check lock TTL must exceed the worst-case check ----------


def test_lock_ttl_defaults_above_interval():
    loop = WorkerHealthLoop("w", MemoryRegistryBackend(), None, interval=30)
    assert loop._lock_ttl == 120
    assert loop._lock_ttl > loop._interval


def test_lock_ttl_scales_with_large_interval():
    loop = WorkerHealthLoop("w", MemoryRegistryBackend(), None, interval=90)
    assert loop._lock_ttl == 180  # max(2 × 90, 120)
    assert loop._lock_ttl > loop._interval


def test_lock_ttl_explicit_override():
    loop = WorkerHealthLoop("w", MemoryRegistryBackend(), None, interval=30, lock_ttl=45)
    assert loop._lock_ttl == 45


@pytest.mark.asyncio
async def test_check_acquires_lock_with_lock_ttl(monkeypatch):
    loop, _backend, _fetch = await _make_loop(monkeypatch)
    captured: dict = {}
    real_set = loop._r.set

    async def _capturing_set(key, value, **kwargs):
        captured.update(kwargs)
        return await real_set(key, value, **kwargs)

    monkeypatch.setattr(loop._r, "set", _capturing_set)

    await loop._check_device("dev1")

    # The lock must be acquired with the long lock TTL, not the short interval.
    assert captured.get("ex") == loop._lock_ttl
    assert captured["ex"] > loop._interval
