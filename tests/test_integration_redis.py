# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Real-Redis integration tests (Plan A).

The unit suite uses fakeredis, which diverges from real Redis in ways that
matter here — notably it doesn't decode hash keys (so DeviceConfig.from_redis_hash
was only ever exercised against stubs) and its pub/sub / consumer-group
semantics aren't identical. These tests run the distributed layer against a real
Redis and skip cleanly when none is reachable.

Run with: pytest -m integration   (needs Redis at MCP_TEST_REDIS_URL)
"""

import asyncio
import json

import pytest

from device_mcp_gateway.shared.registry_backend import (
    DeviceConfig,
    RedisRegistryBackend,
)
from device_mcp_gateway.shared.session_router import SessionRouter
from device_mcp_gateway.worker.runner import DeviceWorker

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


# --- RedisRegistryBackend ---------------------------------------------------


async def test_set_get_device_round_trip(real_redis):
    backend = RedisRegistryBackend(real_redis)
    cfg = DeviceConfig(
        hostname="dev1",
        base_url="http://dev1",
        spec_url="http://dev1/openapi.json",
        rate_limit_rps=5.0,
        pod_active=True,
    )
    await backend.set_device("dev1", cfg)

    # Real Redis decodes responses, so from_redis_hash works end-to-end here
    # (this is the exact path fakeredis could not exercise).
    got = await backend.get_device("dev1")
    assert got is not None
    assert got.hostname == "dev1"
    assert got.base_url == "http://dev1"
    assert got.rate_limit_rps == 5.0
    assert got.pod_active is True
    assert "dev1" in await backend.list_hostnames()


async def test_get_devices_bulk_matches_singles(real_redis):
    backend = RedisRegistryBackend(real_redis)
    for h in ("a", "b", "c"):
        await backend.set_device(h, DeviceConfig(hostname=h, base_url=f"http://{h}"))

    bulk = await backend.get_devices(["a", "b", "missing", "c"])
    assert sorted(d.hostname for d in bulk) == ["a", "b", "c"]


async def test_delete_device_clears_all_keys(real_redis):
    backend = RedisRegistryBackend(real_redis)
    await backend.set_device("dev1", DeviceConfig(hostname="dev1", base_url="http://dev1"))
    await backend.set_manifest("dev1", {"tools": []}, ttl=60)
    await backend.publish_tool_call("dev1", "r1", "s1", "gw", {"method": "tools/list"})

    assert await real_redis.exists("device:dev1:config") == 1
    assert await real_redis.exists("device:dev1:calls") == 1

    await backend.delete_device("dev1")
    assert await real_redis.exists("device:dev1:config") == 0
    assert await real_redis.exists("device:dev1:manifest") == 0
    assert await real_redis.exists("device:dev1:calls") == 0
    assert "dev1" not in await backend.list_hostnames()


# --- SessionRouter (cross-client pub/sub, the F3 path) ----------------------


async def test_register_sets_ttl(real_redis):
    router = SessionRouter(real_redis)
    await router.register("sess1", "dev1", "gw-a", ttl=120)
    assert await router.get("sess1") == {"hostname": "dev1", "gateway_id": "gw-a"}
    ttl = await real_redis.ttl("session:sess1")
    assert 0 < ttl <= 120


async def test_cross_client_pubsub_delivers_result(real_redis):
    # Separate command vs pub/sub clients (as F3 wires them): a result published
    # on one connection must reach a subscriber on the other.
    import redis.asyncio as aioredis
    from tests.conftest import TEST_REDIS_URL

    pubsub_client = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        router = SessionRouter(real_redis, pubsub_client=pubsub_client)
        received = []

        async def _consume():
            async for msg in router.subscribe("s1"):
                received.append(msg)
                break

        task = asyncio.create_task(_consume())
        await asyncio.sleep(0.1)  # let the subscription attach
        await router.publish_result("s1", {"ok": True})
        await asyncio.wait_for(task, timeout=3)
        assert received == [{"ok": True}]
    finally:
        await pubsub_client.aclose()


# --- Worker (claim lease + result marker, real SET NX / TTL) ----------------


async def test_claim_lease_is_exclusive_across_workers(real_redis):
    a = DeviceWorker(worker_id="A", config={}, redis_client=real_redis)
    b = DeviceWorker(worker_id="B", config={}, redis_client=real_redis)

    assert await a._acquire_claim("dev1") is True
    assert await b._acquire_claim("dev1") is False  # B blocked by A's claim
    assert await real_redis.get("claim:dev1") == "A"

    await a._release_claim("dev1")
    assert await b._acquire_claim("dev1") is True  # freed → B can take it


async def test_dispatch_sets_result_marker(real_redis):
    worker = DeviceWorker(worker_id="w1", config={}, redis_client=real_redis)

    class _FakePod:
        async def call_tool(self, message):
            return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}

    worker._pods["dev1"] = _FakePod()
    # Real consumer group so xack at the end is exercised against real Redis.
    await real_redis.xgroup_create("device:dev1:calls", "g", id="0", mkstream=True)
    msg_id = await real_redis.xadd("device:dev1:calls", {"x": "1"})
    fields = {
        "session_id": "s1",
        "request_id": "req1",
        "message": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    }
    await worker._dispatch_call("dev1", "device:dev1:calls", "g", msg_id, fields)

    assert await real_redis.get("result:req1") == "1"


async def test_dispatch_dead_letters_when_no_pod(real_redis):
    """No pod for the device → the call is dead-lettered, the client is told, and
    the original is acked. Exercises XADD/XACK/XPENDING against real Redis (SRE #4)."""
    worker = DeviceWorker(worker_id="w1", config={}, redis_client=real_redis)
    stream, group = "device:dev1:calls", "workers-dev1"
    await real_redis.xgroup_create(stream, group, id="0", mkstream=True)
    msg_id = await real_redis.xadd(stream, {"x": "1"})
    await real_redis.xreadgroup(group, "w1", {stream: ">"}, count=10)  # into PEL

    fields = {
        "session_id": "s1",
        "request_id": "req1",
        "message": json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call"}),
    }
    await worker._dispatch_call("dev1", stream, group, msg_id, fields)

    assert await real_redis.xlen("device:dev1:calls:dead") == 1
    assert await real_redis.get("result:req1") == "1"
    assert (await real_redis.xpending(stream, group))["pending"] == 0


# --- Reconciler end-to-end (real RedisRegistryBackend) — SRE #1/#2 ----------


async def test_reconciler_heals_orphaned_device(real_redis):
    """A device whose owning worker died (claim lease lapsed, stale pod_active in
    Redis) is healed: ownership cleared and an 'assign' republished on the real
    assignments stream. Exercises the RedisRegistryBackend path fakeredis can't."""
    backend = RedisRegistryBackend(real_redis)
    await backend.initialize()
    await backend.set_device(
        "dev1", DeviceConfig(hostname="dev1", base_url="http://dev1", pod_active=True, worker_id="dead-worker")
    )
    worker = DeviceWorker(worker_id="live", config={}, redis_client=real_redis)
    worker._backend = backend

    assert await real_redis.get("claim:dev1") is None  # lease lapsed

    await worker._reconcile_once()

    cfg = await backend.get_device("dev1")
    assert cfg is not None and cfg.pod_active is False and cfg.worker_id is None

    entries = await real_redis.xrange("device:assignments")
    actions = [(f.get("action"), f.get("hostname")) for _id, f in entries]
    assert ("assign", "dev1") in actions


async def test_reconciler_skips_device_with_live_claim(real_redis):
    backend = RedisRegistryBackend(real_redis)
    await backend.initialize()
    await backend.set_device(
        "dev1", DeviceConfig(hostname="dev1", base_url="http://dev1", pod_active=True, worker_id="live")
    )
    await real_redis.set("claim:dev1", "live", ex=60)
    worker = DeviceWorker(worker_id="live", config={}, redis_client=real_redis)
    worker._backend = backend

    await worker._reconcile_once()

    entries = await real_redis.xrange("device:assignments")
    actions = [(f.get("action"), f.get("hostname")) for _id, f in entries]
    assert ("assign", "dev1") not in actions
    cfg = await backend.get_device("dev1")
    assert cfg is not None and cfg.pod_active is True


# --- Durable SSE result delivery (real Redis stream) — SRE #3 ---------------


async def test_result_published_before_subscribe_survives(real_redis):
    """A result appended before the gateway starts reading is still delivered —
    the failure mode the pre-#3 pub/sub path could not survive."""
    import redis.asyncio as aioredis
    from tests.conftest import TEST_REDIS_URL

    pubsub_client = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        router = SessionRouter(real_redis, pubsub_client=pubsub_client)
        await router.publish_result("s1", {"ok": True})  # arrives before any reader

        received = []

        async def _consume():
            async for msg in router.subscribe("s1"):
                received.append(msg)
                break

        await asyncio.wait_for(asyncio.create_task(_consume()), timeout=3)
        assert received == [{"ok": True}]
    finally:
        await pubsub_client.aclose()
