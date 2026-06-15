# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for dead-letter-queue operations (F-10): inspect, replay, drain."""

import copy
from contextlib import asynccontextmanager

import fakeredis.aioredis
import pytest
import yaml
from fastapi.testclient import TestClient

from device_mcp_gateway.main import create_app
from device_mcp_gateway.rbac import Authenticator
from device_mcp_gateway.shared.registry_backend import MemoryRegistryBackend, RedisRegistryBackend


def _backend():
    return RedisRegistryBackend(fakeredis.aioredis.FakeRedis(decode_responses=True))


async def _seed(backend, hostname, n, reason="no active pod"):
    for i in range(n):
        await backend._r.xadd(
            f"device:{hostname}:calls:dead",
            {
                "request_id": f"r{i}",
                "session_id": "s",
                "gateway_id": "g",
                "rid": f"rid{i}",
                "message": '{"method": "tools/call", "id": %d}' % i,
                "reason": reason,
                "ts": "1.0",
            },
        )


# --- backend ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_returns_parsed_entries_newest_first():
    b = _backend()
    await _seed(b, "dev", 3)
    entries = await b.dead_letter_list("dev", count=10)
    assert len(entries) == 3
    assert entries[0]["method"] == "tools/call"
    assert entries[0]["reason"] == "no active pod"
    assert entries[0]["request_id"] == "r2"  # newest first (r2 added last)


@pytest.mark.asyncio
async def test_list_empty_when_no_dlq():
    assert await _backend().dead_letter_list("nope") == []


@pytest.mark.asyncio
async def test_replay_moves_entries_to_call_stream():
    b = _backend()
    await _seed(b, "dev", 3)
    replayed = await b.dead_letter_replay("dev", count=10)
    assert replayed == 3
    assert await b._r.xlen("device:dev:calls") == 3  # re-published
    assert await b._r.xlen("device:dev:calls:dead") == 0  # removed from DLQ
    # The original request_id is preserved on replay.
    entries = await b._r.xrange("device:dev:calls")
    assert any(f.get("request_id") == "r0" for _id, f in entries)


@pytest.mark.asyncio
async def test_replay_specific_ids_only():
    b = _backend()
    await _seed(b, "dev", 3)
    listed = await b.dead_letter_list("dev", count=10)
    one_id = listed[0]["id"]
    replayed = await b.dead_letter_replay("dev", ids=[one_id])
    assert replayed == 1
    assert await b._r.xlen("device:dev:calls:dead") == 2


@pytest.mark.asyncio
async def test_purge_all_drops_stream():
    b = _backend()
    await _seed(b, "dev", 2)
    assert await b.dead_letter_purge("dev") == -1
    assert await b._r.exists("device:dev:calls:dead") == 0


@pytest.mark.asyncio
async def test_purge_specific_ids():
    b = _backend()
    await _seed(b, "dev", 3)
    listed = await b.dead_letter_list("dev", count=10)
    removed = await b.dead_letter_purge("dev", ids=[listed[0]["id"], listed[1]["id"]])
    assert removed == 2
    assert await b._r.xlen("device:dev:calls:dead") == 1


@pytest.mark.asyncio
async def test_memory_backend_dlq_is_noop():
    m = MemoryRegistryBackend()
    assert await m.dead_letter_list("dev") == []
    assert await m.dead_letter_replay("dev") == 0
    assert await m.dead_letter_purge("dev") == 0


# --- endpoints --------------------------------------------------------------


def _distributed_app(backend, monkeypatch):
    cfg = copy.deepcopy(yaml.safe_load(open("config.yaml")))
    cfg.setdefault("registry", {})["mode"] = "distributed"
    cfg.setdefault("gateway", {})["allow_plaintext_credentials"] = True
    cfg["gateway"]["allow_anonymous"] = True
    cfg.setdefault("redis", {})["allow_insecure"] = True
    app = create_app(override_config=cfg)

    @asynccontextmanager
    async def _noop_lifespan(_app):
        yield

    app.router.lifespan_context = _noop_lifespan
    app.state.mode = "distributed"

    class _Reg:
        def __init__(self, b):
            self._backend = b

    app.state.registry = _Reg(backend)
    app.state.redis = backend._r
    monkeypatch.setattr(app.state, "authenticator", Authenticator({}, enabled=False))
    return app


def test_endpoint_list_and_replay_and_purge(monkeypatch):
    import asyncio

    b = _backend()
    asyncio.run(_seed(b, "dev", 3))
    app = _distributed_app(b, monkeypatch)

    with TestClient(app) as client:
        listed = client.get("/v1/devices/dev/deadletter")
        assert listed.status_code == 200
        body = listed.json()
        assert body["count"] == 3 and body["entries"][0]["method"] == "tools/call"

        replay = client.post("/v1/devices/dev/deadletter/replay")
        assert replay.status_code == 200 and replay.json()["replayed"] == 3

        # DLQ now empty; purge of an empty stream removes it.
        purge = client.request("DELETE", "/v1/devices/dev/deadletter")
        assert purge.status_code == 200


def test_endpoint_400_in_embedded_mode(monkeypatch):
    # Default app is embedded — the DLQ endpoints must reject with 400.
    b = _backend()
    app = _distributed_app(b, monkeypatch)
    app.state.mode = "embedded"
    with TestClient(app) as client:
        assert client.get("/v1/devices/dev/deadletter").status_code == 400
