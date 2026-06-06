# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Tests for the distributed tool-call timeout guard (S2 finding F6).

A distributed tool call is fire-and-forget: the gateway publishes to a stream
and returns. If no worker consumes it, the client's SSE stream would hang. The
worker now marks handled calls in Redis; the gateway schedules a watcher that
emits a JSON-RPC timeout error if the marker never appears.
"""

import json

import pytest
import fakeredis.aioredis

from device_mcp_gateway.main import _watch_tool_call_timeout
from device_mcp_gateway.shared.session_router import SessionRouter
from device_mcp_gateway.worker.runner import DeviceWorker


class _SpyRouter(SessionRouter):
    def __init__(self, r):
        super().__init__(r)
        self.published = []

    async def publish_result(self, session_id, result):
        self.published.append((session_id, result))


@pytest.mark.asyncio
async def test_timeout_publishes_error_when_no_worker_responds():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    router = _SpyRouter(r)
    await _watch_tool_call_timeout(r, router, "sess1", "req1", 7, timeout=0.01)

    assert len(router.published) == 1
    session_id, result = router.published[0]
    assert session_id == "sess1"
    assert result["id"] == 7
    assert result["error"]["code"] == -32001


@pytest.mark.asyncio
async def test_timeout_stands_down_when_result_marked():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await r.set("result:req2", "1")
    router = _SpyRouter(r)
    await _watch_tool_call_timeout(r, router, "sess2", "req2", 1, timeout=0.01)

    assert router.published == []  # worker handled it; no error emitted


@pytest.mark.asyncio
async def test_worker_sets_result_marker_after_dispatch():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    worker = DeviceWorker(worker_id="w1", config={}, redis_client=r)

    class _FakePod:
        async def call_tool(self, message):
            return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}

    worker._pods["dev1"] = _FakePod()
    fields = {
        "session_id": "s1",
        "request_id": "req3",
        "message": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    }
    await worker._dispatch_call("dev1", "device:dev1:calls", "g", "0-1", fields)

    assert await r.get("result:req3") == "1"
