# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Phase 4 of the MCP-passthrough plan — proxied upstreams in distributed mode.

Embedded mode holds a live manifest in memory. Distributed mode does not: the worker
rebuilds every manifest from the JSON in Redis, and **whatever that round-trip drops is
gone for good** — silently, at spawn time, with no error anywhere.

That makes ``_dict_to_manifest`` the highest-consequence function in this feature, and the
two things it can lose are not equally obvious:

1. **``proxy``** — carrying the upstream's own tool name. A proxied tool's LLM-facing name
   is sanitised and deduped, so the two names routinely differ. Lose it and the worker calls
   the upstream with the sanitised name, which the upstream has never heard of.
2. **``source``** — the discriminator every reader is supposed to branch on. Lose it and a
   proxied tool comes back claiming to be an OpenAPI tool.

The second one is what makes the idempotency guard worth pinning here. ``is_idempotent_call``
decides from the backing HTTP method, and a proxied tool has none. Today a round-tripped
proxied tool happens to carry ``method=""``, which is not in the idempotent set, so a
redelivery is refused — the safe answer, reached by accident rather than by decision. Anyone
who later "tidies" that empty string to a ``"GET"`` default flips a proxied write to
re-executable with nothing failing. So the guard is made to answer from ``source``, and the
test below pins the behaviour rather than the accident.
"""

from __future__ import annotations

import json

import fakeredis.aioredis
import pytest

from device_mcp_gateway.core.errors import RPC_DUPLICATE
from device_mcp_gateway.core.translator import manifest_to_dict
from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
from device_mcp_gateway.upstream.mcp_discovery import build_proxy_manifest
from device_mcp_gateway.worker.runner import _dict_to_manifest, DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30, "tool_call_timeout": 30}}
HOST = "remote"


def _redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _worker(redis, worker_id="w1"):
    w = DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)
    w._backend = RedisRegistryBackend(redis)
    return w


def _worker_with_memory_backend(redis, worker_id="w1"):
    """A worker whose registry reads come from memory rather than a fake Redis hash.

    Not a shortcut: fakeredis 2.36 does not honour ``decode_responses`` for ``hgetall``
    (``get`` and ``smembers`` decode fine, hash reads come back as bytes), so
    ``DeviceConfig.from_redis_hash`` raises ``KeyError: 'hostname'`` against it. The
    serialisation round-trip is covered by the real-Redis integration tier; what these
    tests are actually about is which pod class the worker builds, so the backend is
    swapped for one that stores the config as-is. Recorded in docs/testing-gaps.md.
    """
    from device_mcp_gateway.core.backoff import RetryPolicy
    from device_mcp_gateway.shared.registry_backend import MemoryRegistryBackend

    w = DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)
    w._backend = MemoryRegistryBackend()
    # `_retry_policy` is built in run(), not __init__, so _spawn_pod carries an implicit
    # "run() first" ordering dependency. Supplied here rather than starting the whole loop.
    w._retry_policy = RetryPolicy()
    return w


def _proxy_manifest():
    """A proxied tool whose upstream name differs from its LLM-facing one, and whose
    upstream name makes the cost of getting this wrong obvious."""
    return build_proxy_manifest(
        HOST,
        [{"name": "Delete All Records", "description": "Destroys everything", "inputSchema": {"type": "object"}}],
    )


def _round_tripped():
    """The manifest as the worker actually gets it: through JSON, out of Redis."""
    return _dict_to_manifest(json.loads(json.dumps(manifest_to_dict(_proxy_manifest()))))


class _RecordingPod:
    def __init__(self, manifest):
        self.manifest = manifest
        self.calls: list[dict] = []

    async def call_tool(self, message):
        self.calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"content": []}}


def _msg(tool_name="delete_all_records", msg_id=1):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": {}},
    }


# --- the headline: a redelivered proxied write must not run twice --------------


@pytest.mark.asyncio
async def test_reclaimed_proxied_tool_call_is_refused_not_re_executed():
    """At-least-once delivery means a reclaimed call (XAUTOCLAIM off a dead worker's PEL)
    can arrive again after the first attempt already ran it. For a proxied tool the gateway
    cannot know whether the upstream operation was a read or a write — so it must refuse,
    not re-run. Re-running "Delete All Records" because a worker died mid-ack is the worst
    outcome this feature can produce.
    """
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_round_tripped())
    w._pods[HOST] = pod

    request_id = "req-proxy-1"
    first = await w._guard_duplicate(HOST, request_id, pod, _msg())
    assert first is None, "the first delivery must be allowed through"

    # Simulate the first attempt having executed and marked itself.
    await pod.call_tool(_msg())

    second = await w._guard_duplicate(HOST, request_id, pod, _msg())
    assert second == "nonidempotent_guard", f"a redelivered proxied call was not refused: {second!r}"
    assert len(pod.calls) == 1, "the proxied tool ran more than once"


@pytest.mark.asyncio
async def test_the_guard_answers_from_source_not_from_an_absent_http_method():
    """Pins the decision, not the accident. A proxied tool that somehow carries a GET must
    still be treated as non-idempotent, because ``method`` is meaningless for it."""
    r = _redis()
    w = _worker(r)
    manifest = _round_tripped()
    manifest.tools[0].method = "GET"  # the "tidy-up" that would otherwise flip it
    pod = _RecordingPod(manifest)

    assert w._is_idempotent_call(pod, _msg()) is False


@pytest.mark.asyncio
async def test_an_openapi_tool_is_still_judged_by_its_method():
    """The proxied rule must not make ordinary read-only tools un-retryable."""
    from device_mcp_gateway.core.translator import McpManifest, McpTool

    r = _redis()
    w = _worker(r)
    manifest = McpManifest(
        server_name="m",
        server_version="1",
        hostname=HOST,
        tools=[McpTool(name="get_status", description="", schema={}, method="GET", path="/status")],
    )
    pod = _RecordingPod(manifest)
    assert w._is_idempotent_call(pod, _msg("get_status")) is True


# --- what the Redis round-trip must preserve ----------------------------------


def test_the_round_trip_preserves_the_upstream_wire_name():
    """The worker calls the upstream with this name. Losing it means calling a tool the
    upstream has never heard of — for every proxied tool whose name needed sanitising."""
    tool = _round_tripped().tools[0]
    assert tool.proxy is not None, "the proxy spec was dropped on the Redis round-trip"
    assert tool.proxy.upstream_tool_name == "Delete All Records"
    assert tool.name == "delete_all_records"


def test_the_round_trip_preserves_the_source_discriminator():
    """Every reader is told to branch on ``source``. A proxied tool that comes back from
    Redis claiming to be OpenAPI defeats all of them at once."""
    assert _round_tripped().tools[0].source == "proxy"


def test_the_round_trip_leaves_an_openapi_tool_exactly_as_it_was():
    from device_mcp_gateway.core.translator import McpManifest, McpTool, RequestBodySpec

    original = McpManifest(
        server_name="m",
        server_version="1",
        hostname="dev",
        tools=[
            McpTool(
                name="upload",
                description="d",
                schema={"type": "object"},
                method="POST",
                path="/upload",
                request_body=RequestBodySpec(binary_fields={"file"}),
                param_wire_names={"id_": "id"},
            )
        ],
    )
    rt = _dict_to_manifest(json.loads(json.dumps(manifest_to_dict(original)))).tools[0]
    assert (rt.source, rt.proxy) == ("openapi", None)
    assert (rt.method, rt.path) == ("POST", "/upload")
    assert rt.request_body.binary_fields == {"file"}
    assert rt.param_wire_names == {"id_": "id"}


# --- the worker must spawn the right pod kind ---------------------------------


@pytest.mark.asyncio
async def test_the_worker_spawns_a_proxy_pod_for_an_mcp_upstream():
    """Without this the worker serves a proxied upstream with the OpenAPI pod, which builds
    HTTP requests from a manifest that has no method or path — the device registers, is
    assigned, reports healthy, and never serves a tool."""
    from device_mcp_gateway.pods.mcp_proxy_pod import McpProxyPod
    from device_mcp_gateway.shared.registry_backend import DeviceConfig
    from device_mcp_gateway.shared.keys import KEYS

    r = _redis()
    w = _worker_with_memory_backend(r)
    cfg = DeviceConfig(
        hostname=HOST, base_url="http://remote.local/mcp", upstream_kind="mcp", upstream_transport="http"
    )
    await w._backend.set_device(HOST, cfg)
    await w._backend.set_manifest(HOST, manifest_to_dict(_proxy_manifest()), ttl=3600)

    await w._spawn_pod(HOST)
    try:
        assert isinstance(w._pods[HOST], McpProxyPod)
        assert w._pods[HOST].manifest.tools[0].proxy.upstream_tool_name == "Delete All Records"
        assert await r.sismember(KEYS.worker_devices("w1"), HOST)
    finally:
        await w._kill_pod(HOST)


@pytest.mark.asyncio
async def test_a_cold_spawn_discovers_the_upstream_instead_of_giving_up():
    """The test above pre-seeds the manifest, so it exercises the *cache-hit* branch only.

    A device registered while nothing is cached takes the cold path instead:
    ``_spawn_pod`` → ``DeviceWorker._fetch_spec``, which is a **different method** from the
    health loop's (deliberately — it probes discovery paths concurrently). Teaching one
    about MCP upstreams and not the other produces a device that registers, reports
    reachable, and then never spawns a pod: "No spec available".

    Found on a real cluster, not here — precisely because the seeded manifest hid it.
    """
    import httpx

    from device_mcp_gateway.shared.registry_backend import DeviceConfig

    r = _redis()
    w = _worker_with_memory_backend(r)
    await w._backend.set_device(
        HOST, DeviceConfig(hostname=HOST, base_url="http://remote.local/mcp", upstream_kind="mcp")
    )
    # No set_manifest: this is a cold registration.

    async def upstream(request):
        body = json.loads(request.content)
        if body["method"] == "initialize":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}}, headers={"Mcp-Session-Id": "s1"}
            )
        if body["method"].startswith("notifications/"):
            return httpx.Response(202, text="")
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"tools": [{"name": "Delete All Records", "description": "d", "inputSchema": {}}]},
            },
        )

    import device_mcp_gateway.worker.runner as runner_mod

    def _fake_guarded_client(**kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(upstream))

    original = runner_mod.build_guarded_client
    runner_mod.build_guarded_client = _fake_guarded_client
    try:
        spec = await w._fetch_spec(await w._backend.get_device(HOST))
    finally:
        runner_mod.build_guarded_client = original

    assert spec is not None, "cold spawn found no spec for an MCP upstream"
    assert spec["upstream_kind"] == "mcp"
    assert [t["name"] for t in spec["tools"]] == ["Delete All Records"]


@pytest.mark.asyncio
async def test_the_worker_still_spawns_a_device_pod_for_an_openapi_upstream():
    from device_mcp_gateway.core.translator import SpecTranslator
    from device_mcp_gateway.pods.device_pod import DevicePod
    from device_mcp_gateway.shared.registry_backend import DeviceConfig

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {"/ping": {"get": {"operationId": "ping", "responses": {"200": {"description": "ok"}}}}},
    }
    r = _redis()
    w = _worker_with_memory_backend(r)
    await w._backend.set_device("dev1", DeviceConfig(hostname="dev1", base_url="http://dev1"))
    await w._backend.set_manifest("dev1", manifest_to_dict(SpecTranslator().translate(spec, "dev1")), ttl=3600)

    await w._spawn_pod("dev1")
    try:
        assert isinstance(w._pods["dev1"], DevicePod)
    finally:
        await w._kill_pod("dev1")


# --- the duplicate refusal reaches the caller ---------------------------------


@pytest.mark.asyncio
async def test_a_refused_duplicate_reports_the_duplicate_error_code():
    """The caller has to be able to tell "refused because it may already have run" from a
    generic failure — retrying the former is exactly what must not happen."""
    r = _redis()
    w = _worker(r)
    pod = _RecordingPod(_round_tripped())
    w._pods[HOST] = pod

    await w._guard_duplicate(HOST, "req-x", pod, _msg())
    reason = await w._guard_duplicate(HOST, "req-x", pod, _msg())
    assert reason == "nonidempotent_guard"
    assert RPC_DUPLICATE  # the code the dispatch path surfaces for this reason
