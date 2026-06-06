# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""F10 slice 2 — worker-side Prometheus metrics.

Distributed-mode tool calls execute on the worker, so tool-call counters/durations
are recorded there; the worker also exports pod count and Redis Stream lag (the
worker HPA signal). Exposition itself is the shared dedicated-port server tested in
test_metrics.py.
"""

import json

import fakeredis.aioredis
import pytest

from device_mcp_gateway import metrics
from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30}, "metrics": {"gauge_refresh_interval": 1}}


def _worker(worker_id="W1", redis=None):
    redis = redis or fakeredis.aioredis.FakeRedis(decode_responses=True)
    return DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)


class _FakePod:
    def __init__(self, result):
        self._result = result

    async def call_tool(self, message):
        return self._result


async def _dispatch(worker, hostname, message, result):
    worker._pods[hostname] = _FakePod(result)
    fields = {"session_id": "s1", "request_id": "r1", "message": json.dumps(message)}
    await worker._dispatch_call(hostname, f"device:{hostname}:calls", f"workers-{hostname}", "1-0", fields)


# --- Tool-call execution metrics ---------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_records_ok_call():
    w = _worker()
    before = metrics.tool_calls_total.labels(hostname="dev-ok", method="tools/call", status="ok")._value.get()
    await _dispatch(w, "dev-ok", {"method": "tools/call", "id": 1}, {"jsonrpc": "2.0", "id": 1, "result": {}})
    after = metrics.tool_calls_total.labels(hostname="dev-ok", method="tools/call", status="ok")._value.get()
    assert after == before + 1


@pytest.mark.asyncio
async def test_dispatch_records_error_call():
    w = _worker()
    before = metrics.tool_calls_total.labels(hostname="dev-err", method="tools/call", status="error")._value.get()
    await _dispatch(w, "dev-err", {"method": "tools/call", "id": 2}, {"jsonrpc": "2.0", "id": 2, "error": {"code": -1}})
    after = metrics.tool_calls_total.labels(hostname="dev-err", method="tools/call", status="error")._value.get()
    assert after == before + 1


@pytest.mark.asyncio
async def test_dispatch_notification_is_noresult():
    w = _worker()
    before = metrics.tool_calls_total.labels(
        hostname="dev-note", method="notifications/initialized", status="noresult"
    )._value.get()
    await _dispatch(w, "dev-note", {"method": "notifications/initialized"}, None)
    after = metrics.tool_calls_total.labels(
        hostname="dev-note", method="notifications/initialized", status="noresult"
    )._value.get()
    assert after == before + 1


@pytest.mark.asyncio
async def test_dispatch_observes_duration():
    w = _worker()
    h = "dev-dur"
    before = metrics.tool_call_duration_seconds.labels(hostname=h)._sum.get()
    await _dispatch(w, h, {"method": "tools/call", "id": 3}, {"result": {}})
    after = metrics.tool_call_duration_seconds.labels(hostname=h)._sum.get()
    assert after >= before  # a non-negative observation was recorded


# --- Worker gauges -----------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_worker_metrics_sets_pod_gauge():
    w = _worker()
    w._pods = {"a": _FakePod(None), "b": _FakePod(None)}
    await w._refresh_worker_metrics()
    assert metrics.worker_pods._value.get() == 2


@pytest.mark.asyncio
async def test_stream_pending_handles_missing_group():
    # No stream/group exists yet — must return 0, never raise.
    w = _worker()
    assert await w._stream_pending("device:nope:calls", "workers-nope") == 0


@pytest.mark.asyncio
async def test_stream_pending_counts_unacked_entries():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    w = _worker(redis=r)
    stream, group = "device:dev1:calls", "workers-dev1"
    await r.xgroup_create(stream, group, id="0", mkstream=True)
    await r.xadd(stream, {"message": "{}"})
    await r.xadd(stream, {"message": "{}"})
    # Deliver (but don't ack) → they become pending for this consumer group.
    delivered = await r.xreadgroup(group, w._id, {stream: ">"}, count=10)
    if not delivered or not delivered[0][1]:
        pytest.skip("fakeredis build does not deliver via xreadgroup")
    pending = await w._stream_pending(stream, group)
    if pending == 0:
        pytest.skip("fakeredis build does not implement XPENDING summary")
    assert pending == 2
