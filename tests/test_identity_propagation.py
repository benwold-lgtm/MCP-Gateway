# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for principal propagation across the call stream (F-30 residual).

The gateway authenticates + authorizes a tool call at the edge and audits it with
the principal `subject`. Per Decision D-1 the worker trusts the stream (single-tenant
boundary), so this is not an isolation gate — but the *audit trail* should not stop at
the gateway. These tests pin that the subject rides the Redis stream entry and is bound
into the worker's execution-audit records, so "who called this tool" is attributable
end-to-end, not just by the `rid` correlation id.
"""

import json

import fakeredis.aioredis
import pytest
from loguru import logger

from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30, "tool_call_timeout": 30}}
HOST = "dev1"


def _redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def audit_records():
    """Capture emitted audit records (event='audit') as a list of `extra` dicts."""
    captured: list[dict] = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    sink_id = logger.add(_sink, level="INFO")
    yield captured
    logger.remove(sink_id)


class _Tool:
    def __init__(self, name, method):
        self.name = name
        self.method = method


class _Manifest:
    def __init__(self, tools):
        self.tools = tools


class _RecordingPod:
    def __init__(self, *tools):
        self.manifest = _Manifest(list(tools))
        self.calls: list[dict] = []

    async def call_tool(self, message):
        self.calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}


def _worker(redis):
    w = DeviceWorker(worker_id="w1", config=CONFIG, redis_client=redis)
    w._backend = RedisRegistryBackend(redis)
    return w


def _msg(tool_name="get_thing", msg_id=1):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": {}},
    }


async def _deliver(redis, fields):
    stream, group = f"device:{HOST}:calls", f"workers-{HOST}"
    try:
        await redis.xgroup_create(stream, group, id="0", mkstream=True)
    except Exception:
        pass
    mid = await redis.xadd(stream, fields)
    await redis.xreadgroup(group, "w1", {stream: ">"}, count=10)
    return stream, group, mid


# --- the subject rides the stream entry --------------------------------------


@pytest.mark.asyncio
async def test_publish_tool_call_writes_subject_to_stream():
    r = _redis()
    backend = RedisRegistryBackend(r)
    await backend.publish_tool_call(
        hostname=HOST,
        request_id="r1",
        session_id="s1",
        gateway_id="gw1",
        message=_msg(),
        rid="rid-1",
        subject="key:ops",
    )
    entries = await r.xrange(f"device:{HOST}:calls")
    assert len(entries) == 1
    _id, fields = entries[0]
    assert fields["subject"] == "key:ops"


@pytest.mark.asyncio
async def test_publish_tool_call_subject_defaults_empty():
    """Back-compat: a caller that omits subject (or an old gateway) writes ''."""
    r = _redis()
    backend = RedisRegistryBackend(r)
    await backend.publish_tool_call(hostname=HOST, request_id="r1", session_id="s1", gateway_id="gw1", message=_msg())
    _id, fields = (await r.xrange(f"device:{HOST}:calls"))[0]
    assert fields["subject"] == ""


# --- the worker binds the subject into its execution audit -------------------


@pytest.mark.asyncio
async def test_worker_audit_carries_subject_on_execution(audit_records):
    r = _redis()
    w = _worker(r)
    w._pods[HOST] = _RecordingPod(_Tool("get_thing", "GET"))
    w._assigned.add(HOST)

    fields = {
        "session_id": "s1",
        "request_id": "r1",
        "rid": "rid-1",
        "subject": "key:ops",
        "message": json.dumps(_msg()),
    }
    s, g, mid = await _deliver(r, fields)
    await w._dispatch_call(HOST, s, g, mid, fields)

    dispatched = [e for e in audit_records if e.get("status") == "ok"]
    assert dispatched, "expected an execution audit record"
    assert dispatched[0]["subject"] == "key:ops"
    assert dispatched[0]["rid"] == "rid-1"


@pytest.mark.asyncio
async def test_worker_audit_subject_falls_back_when_absent(audit_records):
    """A legacy stream entry with no subject field audits subject='-', never KeyErrors."""
    r = _redis()
    w = _worker(r)
    w._pods[HOST] = _RecordingPod(_Tool("get_thing", "GET"))
    w._assigned.add(HOST)

    fields = {
        "session_id": "s1",
        "request_id": "r1",
        "rid": "rid-1",
        "message": json.dumps(_msg()),  # no subject (pre-F-30 producer)
    }
    s, g, mid = await _deliver(r, fields)
    await w._dispatch_call(HOST, s, g, mid, fields)

    dispatched = [e for e in audit_records if e.get("status") == "ok"]
    assert dispatched and dispatched[0]["subject"] == "-"


@pytest.mark.asyncio
async def test_worker_audit_subject_on_dead_letter(audit_records):
    """No pod → dead-letter path still attributes the actor."""
    r = _redis()
    w = _worker(r)  # no pod attached for HOST

    fields = {
        "session_id": "s1",
        "request_id": "r1",
        "rid": "rid-1",
        "subject": "key:ops",
        "message": json.dumps(_msg()),
    }
    s, g, mid = await _deliver(r, fields)
    await w._dispatch_call(HOST, s, g, mid, fields)

    dead = [e for e in audit_records if e.get("status") == "dead_letter"]
    assert dead and dead[0]["subject"] == "key:ops"
