# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for bulk device fetch (S2 finding F5).

list_devices() did list_hostnames() then one get_device() per host — N+1 round
trips on the /health, /metrics/summary, and /devices hot paths. The Redis backend now
fetches all configs in a single pipeline.
"""

import fakeredis.aioredis
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


class _CountingRedis:
    """A real fakeredis client that also counts how many pipelines were opened.

    The count is the point of the test below — ``get_devices`` overrides the default
    one-``get_device``-per-hostname loop precisely to avoid N round trips, and nothing else
    can observe that. Everything else delegates, so the hashes are really written and really
    parsed rather than handed back from a dict.

    This used to be a hand-written stub returning str-keyed hashes, because fakeredis before
    2.37.1 did not decode hash replies and ``from_redis_hash`` could not read them. The floor
    in pyproject.toml is what makes the real client usable here.
    """

    def __init__(self, inner):
        self._inner = inner
        self.pipelines = 0

    def pipeline(self, *a, **kw):
        self.pipelines += 1
        return self._inner.pipeline(*a, **kw)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.mark.asyncio
async def test_redis_get_devices_uses_single_pipeline():
    client = _CountingRedis(fakeredis.aioredis.FakeRedis(decode_responses=True))
    backend = RedisRegistryBackend(client)
    await backend.set_device("a", DeviceConfig(hostname="a", base_url="http://a"))
    await backend.set_device("b", DeviceConfig(hostname="b", base_url="http://b"))
    before = client.pipelines

    got = await backend.get_devices(["a", "b", "gone"])

    assert sorted(c.hostname for c in got) == ["a", "b"]
    assert client.pipelines - before == 1  # one pipeline, not N round-trips


# --- Registry integration ---------------------------------------------------


@pytest.mark.asyncio
async def test_registry_list_devices_distributed_uses_bulk_fetch():
    backend = MemoryRegistryBackend()
    await backend.set_device("a", DeviceConfig(hostname="a", base_url="http://a"))
    await backend.set_device("b", DeviceConfig(hostname="b", base_url="http://b"))
    registry = Registry(config={"mode": "distributed"}, backend=backend)

    devices = await registry.list_devices()
    assert sorted(d.hostname for d in devices) == ["a", "b"]
