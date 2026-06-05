# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Tests for the distributed SSE SessionRouter.

Regression coverage for S1 real-concern RC-2: register() pipelines hset + expire
so a registered session always carries a TTL and cannot leak.
"""

import asyncio

import pytest
import fakeredis.aioredis

from device_mcp_gateway.shared.session_router import SessionRouter, _RefreshThrottle


def _router():
    return SessionRouter(fakeredis.aioredis.FakeRedis(decode_responses=True))


def _norm(d):
    # This fakeredis version doesn't honour decode_responses for hash fields;
    # real Redis decodes, so production get() returns str keys. Normalise here.
    if not d:
        return d
    dec = lambda x: x.decode() if isinstance(x, bytes) else x  # noqa: E731
    return {dec(k): dec(v) for k, v in d.items()}


@pytest.mark.asyncio
async def test_register_sets_fields_and_ttl():
    router = _router()
    await router.register("sess1", "dev1", "gw-a", ttl=3600)

    assert _norm(await router.get("sess1")) == {"hostname": "dev1", "gateway_id": "gw-a"}

    # The hash must carry a TTL — never persist without expiry.
    ttl = await router._r.ttl("session:sess1")
    assert 0 < ttl <= 3600


@pytest.mark.asyncio
async def test_register_always_has_ttl_default():
    router = _router()
    await router.register("sess2", "dev2", "gw-b")  # default 24h TTL
    ttl = await router._r.ttl("session:sess2")
    assert ttl > 0  # -1 (no expiry) would mean the leak this fix prevents


@pytest.mark.asyncio
async def test_get_unknown_returns_none():
    router = _router()
    assert await router.get("missing") is None


@pytest.mark.asyncio
async def test_delete_removes_session():
    router = _router()
    await router.register("sess3", "dev3", "gw-c")
    await router.delete("sess3")
    assert await router.get("sess3") is None


# --- RC-3: throttle TTL refresh on busy streams ----------------------------


def test_refresh_throttle_fires_once_per_window():
    t = _RefreshThrottle(window=60)
    assert t.ready(1000.0) is True  # first call always fires
    assert t.ready(1030.0) is False  # 30s later — within window
    assert t.ready(1059.9) is False  # still within window
    assert t.ready(1060.0) is True  # exactly one window later — fires
    assert t.ready(1100.0) is False  # within the next window


@pytest.mark.asyncio
async def test_subscribe_throttles_refresh_across_rapid_messages(monkeypatch):
    router = _router()
    calls = {"n": 0}

    async def _counting_refresh(session_id, ttl=None):
        calls["n"] += 1

    monkeypatch.setattr(router, "refresh", _counting_refresh)

    results = []

    async def _consume():
        async for r in router.subscribe("busy"):
            results.append(r)
            if len(results) >= 3:
                break

    task = asyncio.create_task(_consume())
    await asyncio.sleep(0.05)  # let the subscriber attach before publishing
    for i in range(3):
        await router.publish_result("busy", {"i": i})
    await asyncio.wait_for(task, timeout=2)

    assert len(results) == 3
    # All three messages land within one 60s throttle window → a single refresh.
    assert calls["n"] == 1
