# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Unit tests for the F-12 registry collaborators (SpecService / PodSupervisor).

The decomposition lets these be tested in isolation — something the Registry
god-object did not allow. SpecService is exercised without any pod machinery, and
PodSupervisor with a stub SpecService, proving the spec↔pod coupling is cut.
"""

from __future__ import annotations

import httpx
import pytest

from device_mcp_gateway.registry.models import DeviceProfile
from device_mcp_gateway.registry.pod_supervisor import PodSupervisor
from device_mcp_gateway.registry.spec_service import SpecCache, SpecService
from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend

_SPEC_V1 = {"openapi": "3.0.3", "info": {"title": "x", "version": "1"}, "paths": {}}
_SPEC_V2 = {
    "openapi": "3.0.3",
    "info": {"title": "x", "version": "2"},
    "paths": {"/h": {"get": {"operationId": "h", "responses": {"200": {"description": "ok"}}}}},
}


def _profile(hostname="dev", base_url="http://dev.local", spec_url=None):
    return DeviceProfile(config=DeviceConfig(hostname=hostname, base_url=base_url, spec_url=spec_url))


class _StubClient:
    is_closed = False

    def __init__(self, body):
        self._body = body

    async def aclose(self):
        self.is_closed = True

    async def get(self, url, timeout=None):
        return httpx.Response(200, json=self._body, request=httpx.Request("GET", url))


async def _spec_service(backend, body):
    from device_mcp_gateway.core.backoff import RetryPolicy

    svc = SpecService(backend=backend, config={}, tls_verify=True, retry_policy=RetryPolicy())
    svc._http_client = _StubClient(body)
    return svc


# --- SpecCache ---------------------------------------------------------------


def test_spec_cache_get_put_invalidate():
    cache = SpecCache(ttl=100, max_entries=2)
    cache.put("a", {"x": 1})
    assert cache.get("a") == {"x": 1}
    cache.invalidate("a")
    assert cache.get("a") is None


def test_spec_cache_evicts_oldest_over_capacity():
    cache = SpecCache(ttl=100, max_entries=2)
    cache.put("a", {"n": 1})
    cache.put("b", {"n": 2})
    cache.put("c", {"n": 3})  # evicts "a" (oldest)
    assert cache.get("a") is None
    assert cache.get("b") == {"n": 2}
    assert cache.get("c") == {"n": 3}


# --- SpecService (no pod knowledge) -----------------------------------------


@pytest.mark.asyncio
async def test_fetch_spec_first_time_returns_false_and_records():
    backend = MemoryRegistryBackend()
    svc = await _spec_service(backend, _SPEC_V1)
    profile = _profile(spec_url="http://dev.local/openapi.json")

    changed = await svc.fetch_spec(profile)
    assert changed is False  # first fetch: no previous hash to differ from
    assert profile.spec_data == _SPEC_V1
    assert profile.config.spec_hash is not None
    await svc.aclose()


@pytest.mark.asyncio
async def test_fetch_spec_reports_changed_on_hash_change():
    backend = MemoryRegistryBackend()
    svc = await _spec_service(backend, _SPEC_V1)
    profile = _profile(spec_url="http://dev.local/openapi.json")
    await svc.fetch_spec(profile)

    # New upstream spec, force a cache miss → should report changed=True.
    svc._http_client = _StubClient(_SPEC_V2)
    svc._cache._store.clear()
    profile.config.last_check = 0.0
    changed = await svc.fetch_spec(profile)
    assert changed is True
    assert profile.spec_data == _SPEC_V2
    await svc.aclose()


# --- PodSupervisor (stub SpecService, no real HTTP) -------------------------


class _StubSpecService:
    """Populates a profile's spec_data on fetch, like the real service would."""

    def __init__(self, spec):
        self._spec = spec
        self.fetch_calls = 0

    async def fetch_spec(self, profile):
        self.fetch_calls += 1
        profile.spec_data = self._spec
        return False


def _pod_supervisor(spec_service, profiles, max_pods=50):
    from device_mcp_gateway.core.backoff import RetryPolicy

    return PodSupervisor(
        backend=MemoryRegistryBackend(),
        config={"max_concurrent_pods": max_pods},
        tls_verify=True,
        retry_policy=RetryPolicy(),
        spec_service=spec_service,
        profiles=profiles,
    )


@pytest.mark.asyncio
async def test_pod_supervisor_spawn_and_kill():
    profile = _profile()
    profiles = {profile.hostname: profile}
    sup = _pod_supervisor(_StubSpecService(_SPEC_V2), profiles)

    await sup.spawn(profile)
    assert profile.pod_active is True
    assert profile.pod is not None
    assert len(profile.pod.manifest.tools) == 1  # /h from spec v2

    await sup.kill(profile)
    assert profile.pod_active is False


@pytest.mark.asyncio
async def test_pod_supervisor_fetches_spec_when_missing():
    profile = _profile()  # no spec_data yet
    stub = _StubSpecService(_SPEC_V2)
    sup = _pod_supervisor(stub, {profile.hostname: profile})

    await sup.spawn(profile)
    assert stub.fetch_calls == 1  # supervisor asked the spec service for the missing spec
    assert profile.pod_active is True
    await sup.kill(profile)


@pytest.mark.asyncio
async def test_pod_supervisor_respects_max_pods():
    busy = _profile("busy")
    busy.config.pod_active = True  # already at the cap of 1
    new = _profile("new")
    profiles = {"busy": busy, "new": new}
    sup = _pod_supervisor(_StubSpecService(_SPEC_V2), profiles, max_pods=1)

    await sup.spawn(new)
    assert new.pod_active is False  # cap reached → not spawned


@pytest.mark.asyncio
async def test_pod_supervisor_no_spec_sets_spawn_error():
    profile = _profile()
    sup = _pod_supervisor(_StubSpecService(None), {profile.hostname: profile})  # fetch yields no spec

    await sup.spawn(profile)
    assert profile.pod_active is False
    assert "No spec available" in (profile.config.spawn_error or "")
