# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The cached manifest is a lease, and the worker serving the device must renew it.

Found on a live cluster, four hours into a run. Both devices reported ``reachable: true``
and ``pod_active: true``, and both answered ``tools/list`` and ``tools/call`` perfectly over
their MCP sessions — while ``GET /devices/{h}/tools`` returned 409, the fleet endpoint
returned 404 "no reachable devices", and diagnostics said ``has_manifest: false,
tool_count: 0``. There were no ``*manifest*`` keys in Redis at all.

The manifest is stored with ``ex=spec_cache_ttl`` (1 h by default) and had exactly two
writers: the spawn path, which runs only when the cache is already empty, and the
changed-spec branch of the health loop. The poll returned early on ``new_hash ==
cfg.spec_hash`` — the normal case for a device whose contract is stable — so nothing
renewed the key. It expired an hour after the pod spawned and stayed gone until the pod
respawned. The pod held its manifest in memory throughout, which is precisely why nothing
looked wrong.

**These tests use a backend that really expires keys and never pre-seed a manifest into the
window under test.** Every test that missed this used ``MemoryRegistryBackend``, which has
no TTL at all, so the expiry path had never once executed.

They run on the **real-Redis tier** (the ``real_redis`` fixture, skipped when no server is
reachable) for two reasons: fakeredis cannot serve this at all — it returns bytes hash
fields despite ``decode_responses=True``, so ``get_device`` blows up on it, which is
[TG-6](../docs/testing-gaps.md) — and a TTL that expires for real is the entire subject
here. CI provides Redis, so this is covered there rather than being locally-only.
"""

import asyncio
import time

import pytest

from device_mcp_gateway.core.translator import SpecTranslator, manifest_to_dict
from device_mcp_gateway.shared.keys import KEYS
from device_mcp_gateway.shared.registry_backend import DeviceConfig, RedisRegistryBackend
from device_mcp_gateway.worker.health import WorkerHealthLoop, spec_fingerprint

pytestmark = pytest.mark.asyncio

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {"/a": {"get": {"operationId": "getA", "responses": {"200": {"description": "ok"}}}}},
}
PROXY_TOOLS = [{"name": "echo", "description": "d", "inputSchema": {"type": "object"}}]


async def _loop(monkeypatch, r, cfg, spec, *, ttl, poll_interval=300):
    """A health loop over one device, backed by real Redis so TTLs actually elapse."""
    import device_mcp_gateway.worker.health as health_mod

    backend = RedisRegistryBackend(r)
    await backend.set_device(cfg.hostname, cfg)

    async def _translate_in_process(_executor, fn, **_kw):
        return fn()

    monkeypatch.setattr(health_mod, "run_translation", _translate_in_process)
    loop = WorkerHealthLoop(
        worker_id="w1",
        backend=backend,
        redis_client=r,
        interval=30,
        spec_poll_interval=poll_interval,
        spec_cache_ttl=ttl,
    )

    async def _reach(_cfg):
        return True

    async def _fetch(_cfg):
        return spec

    monkeypatch.setattr(loop, "_check_reachability", _reach)
    monkeypatch.setattr(loop, "_fetch_spec", _fetch)
    return loop, backend, r


async def _poll(loop, hostname):
    """Force one *polling* cycle — the first cycle only seeds the poll timestamp."""
    loop._last_spec_check[hostname] = time.time() - 10_000
    await loop._check_device(hostname)


def _spawned_manifest(spec, hostname):
    """What the spawn path stores, so the tests start where a real pod leaves off."""
    return manifest_to_dict(SpecTranslator().translate(spec, hostname))


async def test_an_unchanged_spec_still_renews_the_manifest_lease(monkeypatch, real_redis):
    """The regression itself. A stable device polled repeatedly must never lose its cache."""
    cfg = DeviceConfig(
        hostname="dev1",
        base_url="http://dev1",
        spec_url="http://dev1/openapi.json",
        spec_hash=spec_fingerprint(SPEC, is_proxy=False),
    )
    loop, backend, r = await _loop(monkeypatch, real_redis, cfg, SPEC, ttl=2)
    await backend.set_manifest("dev1", _spawned_manifest(SPEC, "dev1"), ttl=2)

    # Poll inside the window, twice, spanning more than the original TTL. Before the fix
    # the key's TTL only ever counted down, so it was gone by the end of this loop.
    for _ in range(3):
        await asyncio.sleep(0.8)
        await _poll(loop, "dev1")

    assert await r.ttl(KEYS.device_manifest("dev1")) > 0
    assert await backend.get_manifest("dev1") is not None


async def test_a_lapsed_manifest_is_rebuilt_rather_than_left_empty(monkeypatch, real_redis):
    """A worker that was down while the cache expired must restore it, not wait for a respawn."""
    cfg = DeviceConfig(
        hostname="dev1",
        base_url="http://dev1",
        spec_url="http://dev1/openapi.json",
        spec_hash=spec_fingerprint(SPEC, is_proxy=False),
    )
    loop, backend, r = await _loop(monkeypatch, real_redis, cfg, SPEC, ttl=1)
    await backend.set_manifest("dev1", _spawned_manifest(SPEC, "dev1"), ttl=1)

    await asyncio.sleep(1.3)
    assert await backend.get_manifest("dev1") is None, "precondition: the cache really expired"

    await _poll(loop, "dev1")

    restored = await backend.get_manifest("dev1")
    assert restored is not None, "a healthy device must not stay uncacheable until its pod respawns"
    assert [t["name"] for t in restored["tools"]] == [t["name"] for t in _spawned_manifest(SPEC, "dev1")["tools"]]
    assert await r.ttl(KEYS.device_manifest("dev1")) > 0


async def test_rebuilding_a_lapsed_cache_is_not_reported_as_a_tool_change(monkeypatch, real_redis):
    """The spec hash is unchanged, so the tool set is unchanged. Recording a diff here would
    fire a breaking-change alert every time a cache happened to lapse."""
    cfg = DeviceConfig(
        hostname="dev1",
        base_url="http://dev1",
        spec_url="http://dev1/openapi.json",
        spec_hash=spec_fingerprint(SPEC, is_proxy=False),
        tools_revision=4,
    )
    loop, backend, _ = await _loop(monkeypatch, real_redis, cfg, SPEC, ttl=1)
    await backend.set_manifest("dev1", _spawned_manifest(SPEC, "dev1"), ttl=1)
    await asyncio.sleep(1.3)

    await _poll(loop, "dev1")

    stored = await backend.get_device("dev1")
    assert stored.tools_revision == 4, "a cache rebuild is not a revision bump"
    assert await backend.get_last_tool_change("dev1") is None


async def test_a_proxied_mcp_upstream_gets_the_same_lease_treatment(monkeypatch, real_redis):
    """Passthrough devices cache a manifest too, and rebuild without going through translation."""
    cfg = DeviceConfig(
        hostname="mcp1",
        base_url="http://mcp1/mcp",
        upstream_kind="mcp",
        spec_hash=spec_fingerprint({"tools": PROXY_TOOLS}, is_proxy=True),
    )
    loop, backend, r = await _loop(monkeypatch, real_redis, cfg, {"tools": PROXY_TOOLS}, ttl=1)
    await backend.set_manifest("mcp1", {"tools": [{"name": "echo"}]}, ttl=1)
    await asyncio.sleep(1.3)
    assert await backend.get_manifest("mcp1") is None

    await _poll(loop, "mcp1")

    restored = await backend.get_manifest("mcp1")
    assert restored is not None
    assert [t["name"] for t in restored["tools"]] == ["echo"]
    assert await r.ttl(KEYS.device_manifest("mcp1")) > 0


async def test_touch_reports_whether_there_was_a_lease_to_renew(real_redis):
    """The rebuild branch hangs off this return value, so it has to be honest about a missing key."""
    backend = RedisRegistryBackend(real_redis)
    r = real_redis

    assert await backend.touch_manifest("nobody", 60) is False

    await backend.set_manifest("dev1", {"tools": []}, ttl=1)
    assert await backend.touch_manifest("dev1", 60) is True
    assert await r.ttl(KEYS.device_manifest("dev1")) > 1  # and it really extended it
