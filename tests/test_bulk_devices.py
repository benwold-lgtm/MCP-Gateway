# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for bulk device fetch (S2 finding F5).

list_devices() did list_hostnames() then one get_device() per host — N+1 round
trips on the /health, /metrics/summary, and /devices hot paths. The Redis backend now
fetches all configs in a single pipeline.
"""

import pytest

from device_mcp_gateway.shared.registry_backend import (
    DeviceConfig,
    MemoryRegistryBackend,
    RedisRegistryBackend,
)
from device_mcp_gateway.registry.server import Registry

# --- Memory backend default implementation ---------------------------------


@pytest.mark.asyncio
async def test_memory_get_devices_returns_requested_and_skips_missing():
    backend = MemoryRegistryBackend()
    await backend.set_device("a", DeviceConfig(hostname="a", base_url="http://a"))
    await backend.set_device("b", DeviceConfig(hostname="b", base_url="http://b"))

    got = await backend.get_devices(["a", "missing", "b"])
    assert sorted(c.hostname for c in got) == ["a", "b"]


@pytest.mark.asyncio
async def test_memory_get_devices_empty():
    assert await MemoryRegistryBackend().get_devices([]) == []


# --- Redis backend single-pipeline override --------------------------------


class _StubPipe:
    def __init__(self, store):
        self._store = store
        self._keys: list[str] = []

    def hgetall(self, key):
        self._keys.append(key)

    async def execute(self):
        return [self._store.get(k, {}) for k in self._keys]


class _StubRedis:
    """Minimal redis stub returning str-keyed hashes (real Redis decodes; this
    sidesteps the fakeredis byte-key quirk so from_redis_hash works)."""

    def __init__(self, store):
        self._store = store
        self.pipelines = 0

    def pipeline(self):
        self.pipelines += 1
        return _StubPipe(self._store)


@pytest.mark.asyncio
async def test_redis_get_devices_uses_single_pipeline():
    store = {
        "device:a:config": {"hostname": "a", "base_url": "http://a"},
        "device:b:config": {"hostname": "b", "base_url": "http://b"},
    }
    stub = _StubRedis(store)
    backend = RedisRegistryBackend(stub)

    got = await backend.get_devices(["a", "b", "gone"])
    assert sorted(c.hostname for c in got) == ["a", "b"]
    assert stub.pipelines == 1  # one pipeline, not N round-trips


# --- Registry integration ---------------------------------------------------


@pytest.mark.asyncio
async def test_registry_list_devices_distributed_uses_bulk_fetch():
    backend = MemoryRegistryBackend()
    await backend.set_device("a", DeviceConfig(hostname="a", base_url="http://a"))
    await backend.set_device("b", DeviceConfig(hostname="b", base_url="http://b"))
    registry = Registry(config={"mode": "distributed"}, backend=backend)

    devices = await registry.list_devices()
    assert sorted(d.hostname for d in devices) == ["a", "b"]
