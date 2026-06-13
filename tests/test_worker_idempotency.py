# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for the worker idempotency guard (F-08).

At-least-once stream delivery means a reclaimed call (XAUTOCLAIM from a dead/shed
worker's PEL) can re-run an operation that already executed. The guard runs a
non-idempotent call (POST/PATCH) at most once across the fleet, while still
re-running idempotent calls (GET/PUT/DELETE/…) freely.
"""

import json

import fakeredis.aioredis
import pytest

from device_mcp_gateway.core.errors import RPC_DUPLICATE
from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30, "tool_call_timeout": 30}}
HOST = "dev1"


def _redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _worker(redis, worker_id="w1", config=CONFIG):
    w = DeviceWorker(worker_id=worker_id, config=config, redis_client=redis)
    w._backend = RedisRegistryBackend(redis)
    return w


class _Tool:
    def __init__(self, name, method):
        self.name = name
        self.method = method


class _Manifest:
    def __init__(self, tools):
        self.tools = tools


class _RecordingPod:
    """Stub pod that records every executed call so double-runs are visible."""

    def __init__(self, *tools):
        self.manifest = _Manifest(list(tools))
        self.calls: list[dict] = []

    async def call_tool(self, message):
        self.calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}


def _msg(tool_name, msg_id=1):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": {}},
    }


def _fields(message, request_id="r1", session_id="s1"):
    return {
        "session_id": session_id,
        "request_id": request_id,
        "rid": "rid-1",
        "message": json.dumps(message),
    }


async def _attach_pod(worker, pod, hostname=HOST):
    worker._pods[hostname] = pod
    worker._assigned.add(hostname)


async def _deliver(redis, hostname, fields):
    """XADD a call onto the device stream + deliver it to the group (into the PEL),
    returning (stream, group, msg_id) so _dispatch_call's xack has something to ack."""
    stream, group = f"device:{hostname}:calls", f"workers-{hostname}"
    try:
        await redis.xgroup_create(stream, group, id="0", mkstream=True)
    except Exception:
        pass
    mid = await redis.xadd(stream, fields)
    await redis.xreadgroup(group, "w1", {stream: ">"}, count=10)
    return stream, group, mid


async def _results(redis, session_id="s1"):
    entries = await redis.xrange(f"session:{session_id}:results")
    return [json.loads(f["data"]) for _id, f in entries]


# --- method classification ---------------------------------------------------


@pytest.mark.asyncio
async def test_is_idempotent_by_http_method():
    w = _worker(_redis())
    pod = _RecordingPod(_Tool("get_thing", "GET"), _Tool("make_thing", "POST"), _Tool("set_thing", "PUT"))
    assert w._is_idempotent_call(pod, _msg("get_thing")) is True
    assert w._is_idempotent_call(pod, _msg("set_thing")) is True  # PUT is idempotent
    assert w._is_idempotent_call(pod, _msg("make_thing")) is False  # POST is not


@pytest.mark.asyncio
async def test_non_toolcall_and_unknown_tool_are_idempotent():
    w = _worker(_redis())
    pod = _RecordingPod(_Tool("make_thing", "POST"))
    assert w._is_idempotent_call(pod, {"method": "tools/list", "id": 1}) is True
    assert w._is_idempotent_call(pod, {"method": "resources/read", "id": 1}) is True
    assert w._is_idempotent_call(pod, _msg("does_not_exist")) is True  # no upstream call → safe


# --- guard decision ----------------------------------------------------------


@pytest.mark.asyncio
async def test_guard_allows_first_nonidempotent_then_refuses_replay():
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_Tool("make_thing", "POST"))
    # First delivery: no markers yet → proceed, and the started-marker is claimed.
    assert await w._guard_duplicate(HOST, "r1", pod, _msg("make_thing")) is None
    assert await r.get("exec:r1") == "w1"
    # A redelivery before the result was recorded (prior attempt began, then the
    # worker died) → refuse rather than double-apply.
    assert await w._guard_duplicate(HOST, "r1", pod, _msg("make_thing")) == "nonidempotent_guard"


@pytest.mark.asyncio
async def test_guard_allows_idempotent_replay():
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_Tool("get_thing", "GET"))
    assert await w._guard_duplicate(HOST, "r1", pod, _msg("get_thing")) is None
    # Re-run is harmless for a GET — still allowed, and no started-marker is taken.
    assert await w._guard_duplicate(HOST, "r1", pod, _msg("get_thing")) is None
    assert await r.get("exec:r1") is None


@pytest.mark.asyncio
async def test_guard_dedups_completed_call_any_method():
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_Tool("make_thing", "POST"))
    await r.set("result:r1", "1")  # a result was already published
    assert await w._guard_duplicate(HOST, "r1", pod, _msg("make_thing")) == "already_completed"


# --- full dispatch path ------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_runs_nonidempotent_once_on_redelivery():
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_Tool("make_thing", "POST"))
    await _attach_pod(w, pod)
    fields = _fields(_msg("make_thing"), request_id="r1")

    s, g, mid1 = await _deliver(r, HOST, fields)
    await w._dispatch_call(HOST, s, g, mid1, fields)
    assert len(pod.calls) == 1  # executed once
    assert await r.exists("result:r1")  # completion recorded

    # Reclaim/redelivery of the same call → must NOT execute again.
    _s, _g, mid2 = await _deliver(r, HOST, fields)
    await w._dispatch_call(HOST, s, g, mid2, fields)
    assert len(pod.calls) == 1  # still once — duplicate suppressed


@pytest.mark.asyncio
async def test_dispatch_refuses_when_prior_attempt_began():
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_Tool("make_thing", "POST"))
    await _attach_pod(w, pod)
    # A now-dead worker began this op (started-marker) but never recorded a result.
    await r.set("exec:r9", "dead-worker")
    fields = _fields(_msg("make_thing", msg_id=42), request_id="r9")
    s, g, mid = await _deliver(r, HOST, fields)

    await w._dispatch_call(HOST, s, g, mid, fields)

    assert pod.calls == []  # refused — not re-executed
    # Client is told definitively instead of hanging to the timeout.
    results = await _results(r)
    assert len(results) == 1
    assert results[0]["id"] == 42
    assert results[0]["error"]["code"] == RPC_DUPLICATE
    assert results[0]["error"]["data"]["reason"] == "duplicate_suppressed"
    # And the gateway's timeout watcher stands down.
    assert await r.exists("result:r9")


@pytest.mark.asyncio
async def test_dispatch_reexecutes_idempotent_on_redelivery():
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_Tool("get_thing", "GET"))
    await _attach_pod(w, pod)
    fields = _fields(_msg("get_thing"), request_id="r1")

    s, g, mid1 = await _deliver(r, HOST, fields)
    await w._dispatch_call(HOST, s, g, mid1, fields)
    # Clear the completion marker to simulate a redelivery that lost the result
    # (e.g. published to a gateway replica that dropped); a GET is safe to repeat.
    await r.delete("result:r1")
    _s, _g, mid2 = await _deliver(r, HOST, fields)
    await w._dispatch_call(HOST, s, g, mid2, fields)
    assert len(pod.calls) == 2  # GET re-run is allowed


@pytest.mark.asyncio
async def test_dispatch_guard_disabled_allows_double_execute():
    r = _redis()
    cfg = {"registry": {"health_check_interval": 30, "idempotency_guard": False}}
    w = _worker(r, config=cfg)
    pod = _RecordingPod(_Tool("make_thing", "POST"))
    await _attach_pod(w, pod)
    fields = _fields(_msg("make_thing"), request_id="r1")

    s, g, mid1 = await _deliver(r, HOST, fields)
    await w._dispatch_call(HOST, s, g, mid1, fields)
    _s, _g, mid2 = await _deliver(r, HOST, fields)
    await w._dispatch_call(HOST, s, g, mid2, fields)
    assert len(pod.calls) == 2  # guard off → at-least-once for every method
