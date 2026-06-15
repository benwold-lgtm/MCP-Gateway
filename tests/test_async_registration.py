# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for async device registration + parallel spec discovery (F-11).

Registration provisions (reachability + spec discovery + pod spawn) off the
POST /devices request path: a fast/healthy device still returns ready within the
inline budget, while a slow/unreachable one returns promptly with the work
continuing in the background. Spec discovery probes candidate paths concurrently
so worst-case latency is one path's timeout, not the sum of all of them.
"""

import asyncio
import time
from unittest.mock import AsyncMock

import httpx
import pytest

from device_mcp_gateway.registry.server import Registry

# --- async registration ------------------------------------------------------


@pytest.mark.asyncio
async def test_registration_returns_within_budget_and_provisions_in_background():
    registry = Registry(config={"registration_provision_budget": 0.2, "health_check_interval": 10})
    release = asyncio.Event()

    async def slow_reach(profile):
        await release.wait()  # outlives the inline budget
        profile.config.reachable = True
        return True

    registry.check_reachability = slow_reach
    registry._spec_service.fetch_spec = AsyncMock(return_value=False)
    registry._pod_supervisor.spawn = AsyncMock()

    t0 = time.monotonic()
    cfg = await registry.register_device(hostname="slow", base_url="http://slow.local")
    elapsed = time.monotonic() - t0

    # Returned at the budget rather than blocking on the slow reachability probe.
    assert elapsed < 1.0
    assert cfg.pod_active is False
    assert registry.is_provisioning("slow") is True

    task = registry._provision_tasks["slow"]
    release.set()  # let the background task finish
    await task
    assert registry.is_provisioning("slow") is False
    await registry.shutdown()


@pytest.mark.asyncio
async def test_fast_registration_returns_ready_and_not_provisioning():
    registry = Registry(config={"health_check_interval": 10})
    registry.check_reachability = AsyncMock(return_value=True)

    async def fake_fetch(profile):
        profile.spec_data = {"openapi": "3.0.0"}
        return False

    async def fake_spawn(profile):
        profile.config.pod_active = True

    registry._spec_service.fetch_spec = fake_fetch
    registry._pod_supervisor.spawn = fake_spawn

    cfg = await registry.register_device(hostname="fast", base_url="http://fast.local")

    # Provisioning completed inline within the budget — response reflects the pod.
    assert cfg.pod_active is True
    assert registry.is_provisioning("fast") is False
    await registry.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_pending_provisioning():
    registry = Registry(config={"registration_provision_budget": 0.1})
    never = asyncio.Event()

    async def hang(profile):
        await never.wait()
        return False

    registry.check_reachability = hang
    await registry.register_device(hostname="hang", base_url="http://hang.local")
    assert registry.is_provisioning("hang") is True

    await registry.shutdown()  # must cancel the in-flight provisioning task
    assert registry._provision_tasks == {}


# --- parallel spec discovery -------------------------------------------------


class _FakeClient:
    """Returns a per-path response after a per-path delay; mimics httpx client."""

    is_closed = False

    def __init__(self, behaviors):
        self._behaviors = behaviors  # path-suffix -> (delay_s, spec_dict_or_None)

    async def aclose(self):
        self.is_closed = True

    async def get(self, url, timeout=None):
        for suffix, (delay, body) in self._behaviors.items():
            if url.endswith(suffix):
                await asyncio.sleep(delay)
                if body is None:
                    return httpx.Response(404, json={}, request=httpx.Request("GET", url))
                return httpx.Response(200, json=body, request=httpx.Request("GET", url))
        return httpx.Response(404, json={}, request=httpx.Request("GET", url))


@pytest.mark.asyncio
async def test_discover_spec_parallel_first_valid_wins():
    spec = {"openapi": "3.0.0", "info": {"title": "x", "version": "1"}, "paths": {}}
    registry = Registry(config={"discovery": {"timeout": 5}})
    # The preferred path is slow + has no spec; a later path answers fast with one.
    registry._spec_service._http_client = _FakeClient(
        {
            "/openapi.json": (0.6, None),
            "/swagger.json": (0.05, spec),
            "/api-docs": (0.6, None),
        }
    )

    t0 = time.monotonic()
    result = await registry._spec_service._discover_spec("http://x.local")
    elapsed = time.monotonic() - t0

    assert result == spec
    # Parallel: bounded by the winner (~0.05s), not the serial sum (~1.25s).
    assert elapsed < 0.4
    await registry.shutdown()


@pytest.mark.asyncio
async def test_discover_spec_returns_none_when_no_path_has_spec():
    registry = Registry(config={"discovery": {"timeout": 5}})
    registry._spec_service._http_client = _FakeClient(
        {"/openapi.json": (0.02, None), "/swagger.json": (0.02, None), "/api-docs": (0.02, None)}
    )
    assert await registry._spec_service._discover_spec("http://x.local") is None
    await registry.shutdown()
