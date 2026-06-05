# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Tests for RedisRegistryBackend.

Regression coverage for S1 real-concern RC-4: delete_device() must remove the
device's tool-call stream as well as its config/manifest, or the stream lingers
in Redis and accumulates across device churn.
"""

import pytest
import fakeredis.aioredis

from device_mcp_gateway.shared.registry_backend import DeviceConfig, RedisRegistryBackend


def _backend():
    return RedisRegistryBackend(fakeredis.aioredis.FakeRedis(decode_responses=True))


@pytest.mark.asyncio
async def test_delete_device_removes_all_keys_including_call_stream():
    backend = _backend()
    r = backend._r
    host = "dev1"

    await backend.set_device(host, DeviceConfig(hostname=host, base_url="http://dev1"))
    await backend.set_manifest(host, {"tools": []}, ttl=3600)
    await backend.publish_tool_call(
        hostname=host,
        request_id="r1",
        session_id="s1",
        gateway_id="gw-a",
        message={"method": "tools/list"},
    )

    # Precondition: all four artifacts exist.
    assert await r.exists(f"device:{host}:config") == 1
    assert await r.exists(f"device:{host}:manifest") == 1
    assert await r.exists(f"device:{host}:calls") == 1
    assert host in await backend.list_hostnames()

    await backend.delete_device(host)

    # The call stream must be gone along with everything else (RC-4).
    assert await r.exists(f"device:{host}:config") == 0
    assert await r.exists(f"device:{host}:manifest") == 0
    assert await r.exists(f"device:{host}:calls") == 0
    assert host not in await backend.list_hostnames()
