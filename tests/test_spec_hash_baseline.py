# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The tool-change governance baseline: ``spec_hash`` must get written in distributed mode.

Found on a live cluster. The health loop compared each poll against
``cfg.spec_hash`` — but the only writers of that field were ``SpecService.fetch_spec``
and ``McpDiscoveryService.fetch_spec``, both of which run in the **registry**, which
distributed mode does not run. So the field stayed empty forever, the
``if cfg.spec_hash and ...`` guard was permanently false, and the branch that would
have written the baseline sat inside the branch that could never be entered.

The effect was not a missed hash. It was that F-41 tool-change governance — breaking-change
detection, ``tools_revision``, ``GET /tools/diff``, the breaking-change alert — could
**never fire in the mode we ship**, for either upstream kind. A tool could be removed from
a device, or a description rewritten into a prompt-injection payload, and the gateway would
keep serving the old manifest and say nothing.

Every pre-existing governance test constructed its device with ``spec_hash`` already set,
which is exactly the state the system never reaches on its own. These start from the state
a real registration produces: empty.
"""

import hashlib
import time

import fakeredis.aioredis
import pytest

from device_mcp_gateway.core.translator import SpecTranslator, manifest_to_dict
from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend
from device_mcp_gateway.upstream.mcp_discovery import build_proxy_manifest, canonical_tools_hash
from device_mcp_gateway.worker.health import WorkerHealthLoop, spec_fingerprint


def _manifest_for(spec, hostname):
    """The manifest the spawn path would have stored for this spec."""
    return manifest_to_dict(SpecTranslator().translate(spec, hostname))


SPEC_V1 = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {"/a": {"get": {"operationId": "getA", "responses": {"200": {"description": "ok"}}}}},
}
SPEC_V2 = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {"/b": {"get": {"operationId": "getB", "responses": {"200": {"description": "ok"}}}}},
}

TOOLS_V1 = [{"name": "echo", "description": "d", "inputSchema": {"type": "object"}}]
TOOLS_V2 = [{"name": "wipe", "description": "d", "inputSchema": {"type": "object"}}]


async def _loop(monkeypatch, cfg, spec_box, manifest=None):
    """A health loop over one device, with reachability and spec fetching stubbed.

    ``spec_box["spec"]`` is what the upstream currently serves; rebinding it between
    cycles is how these tests change a device's contract underneath the gateway.

    ``manifest`` is what the spawn path already stored — the diff is taken against that,
    not against the previous spec, so a test that omits it sees every tool as added.
    """
    import device_mcp_gateway.worker.health as health_mod

    backend = MemoryRegistryBackend()
    await backend.set_device(cfg.hostname, cfg)
    if manifest is not None:
        await backend.set_manifest(cfg.hostname, manifest, ttl=3600)

    async def _translate_in_process(_executor, fn, **_kw):
        # The real path hands OpenAPI translation to a ProcessPoolExecutor; running it
        # in-process keeps these tests about governance rather than about the pool.
        return fn()

    monkeypatch.setattr(health_mod, "run_translation", _translate_in_process)
    loop = WorkerHealthLoop(
        worker_id="w1",
        backend=backend,
        redis_client=fakeredis.aioredis.FakeRedis(decode_responses=True),
        interval=30,
        spec_poll_interval=300,
    )
    replaced: list[str] = []

    async def _reach(_cfg):
        return True

    async def _fetch(_cfg):
        return spec_box["spec"]

    async def _on_changed(hostname):
        replaced.append(hostname)

    monkeypatch.setattr(loop, "_check_reachability", _reach)
    monkeypatch.setattr(loop, "_fetch_spec", _fetch)
    loop.on_spec_changed = _on_changed
    return loop, backend, replaced


async def _poll(loop, hostname):
    """Force one *polling* cycle (the first cycle only seeds the poll timestamp)."""
    loop._last_spec_check[hostname] = time.time() - 10_000
    await loop._check_device(hostname)


# --- the baseline gets written at all ---------------------------------------


@pytest.mark.asyncio
async def test_a_poll_seeds_the_spec_hash_when_the_device_has_none(monkeypatch):
    """A device registered in distributed mode starts with no hash. Something must write one,
    or every later comparison is against nothing."""
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1", spec_url="http://dev1/openapi.json")
    assert cfg.spec_hash is None  # the state a real registration produces
    loop, backend, _ = await _loop(monkeypatch, cfg, {"spec": SPEC_V1})

    await _poll(loop, "dev1")

    stored = await backend.get_device("dev1")
    assert stored.spec_hash == spec_fingerprint(SPEC_V1, is_proxy=False)


@pytest.mark.asyncio
async def test_seeding_is_not_reported_as_a_change(monkeypatch):
    """First sighting is not a rug-pull. Recording a diff here would report a device's whole
    tool set as 'added' on every worker restart, and cry breaking change each time."""
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1", spec_url="http://dev1/openapi.json")
    loop, backend, replaced = await _loop(monkeypatch, cfg, {"spec": SPEC_V1})

    await _poll(loop, "dev1")

    stored = await backend.get_device("dev1")
    assert stored.tools_revision in (0, None)
    assert await backend.get_last_tool_change("dev1") is None
    assert replaced == []  # and no pointless pod replacement


# --- and the change that follows is actually caught --------------------------


@pytest.mark.asyncio
async def test_a_change_after_seeding_is_detected_and_recorded(monkeypatch):
    """The whole point: poll, then change the upstream, and the second poll must notice.

    Against the unfixed code this fails at the first assertion — nothing was ever seeded,
    so the second poll has nothing to compare against either.
    """
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1", spec_url="http://dev1/openapi.json")
    box = {"spec": SPEC_V1}
    loop, backend, replaced = await _loop(monkeypatch, cfg, box, manifest=_manifest_for(SPEC_V1, "dev1"))

    await _poll(loop, "dev1")  # seeds
    box["spec"] = SPEC_V2  # the contract changes underneath us
    await _poll(loop, "dev1")  # must detect

    stored = await backend.get_device("dev1")
    assert stored.spec_hash == spec_fingerprint(SPEC_V2, is_proxy=False)
    assert stored.tools_revision == 1
    change = await backend.get_last_tool_change("dev1")
    assert change is not None, "tool change went unrecorded"
    assert change["removed"] == ["geta"]
    assert change["added"] == ["getb"]
    assert change["breaking"] is True
    assert replaced == ["dev1"]


@pytest.mark.asyncio
async def test_an_mcp_upstream_is_governed_the_same_way(monkeypatch):
    """Proxied upstreams are the ones this protects against: an untrusted MCP server can
    change its own tools between polls, which an OpenAPI document cannot do by itself."""
    cfg = DeviceConfig(hostname="up1", base_url="http://up1/mcp", upstream_kind="mcp")
    box = {"spec": {"upstream_kind": "mcp", "tools": TOOLS_V1}}
    loop, backend, replaced = await _loop(
        monkeypatch, cfg, box, manifest=manifest_to_dict(build_proxy_manifest("up1", TOOLS_V1))
    )

    await _poll(loop, "up1")
    seeded = await backend.get_device("up1")
    assert seeded.spec_hash == canonical_tools_hash(TOOLS_V1)

    box["spec"] = {"upstream_kind": "mcp", "tools": TOOLS_V2}
    await _poll(loop, "up1")

    stored = await backend.get_device("up1")
    change = await backend.get_last_tool_change("up1")
    assert stored.tools_revision == 1
    assert change["removed"] == ["echo"]
    assert change["breaking"] is True
    assert replaced == ["up1"]


@pytest.mark.asyncio
async def test_a_reordered_tools_list_is_still_not_a_change(monkeypatch):
    """Seeding must use the canonical projection, not ``str(spec)``. Hashing the raw response
    would make every poll of an MCP upstream look like a change, since ``tools/list`` ordering
    is server-controlled — a fleet-wide pod-replace loop."""
    tools = [
        {"name": "a", "description": "d", "inputSchema": {"type": "object"}},
        {"name": "b", "description": "d", "inputSchema": {"type": "object"}},
    ]
    cfg = DeviceConfig(hostname="up1", base_url="http://up1/mcp", upstream_kind="mcp")
    box = {"spec": {"upstream_kind": "mcp", "tools": tools}}
    loop, backend, replaced = await _loop(monkeypatch, cfg, box)

    await _poll(loop, "up1")
    box["spec"] = {"upstream_kind": "mcp", "tools": list(reversed(tools))}
    await _poll(loop, "up1")

    assert replaced == []
    assert await backend.get_last_tool_change("up1") is None


# --- the spawn path writes the baseline it actually built the manifest from ---


@pytest.mark.asyncio
async def test_a_cold_spawn_persists_the_hash_of_the_spec_it_used():
    """Seeding on the first poll leaves a window: a change arriving before that poll gets
    adopted silently as the baseline. The spawn path already holds the spec it built the
    manifest from, so that is where the baseline belongs.
    """
    from device_mcp_gateway.core.backoff import RetryPolicy
    from device_mcp_gateway.worker.runner import DeviceWorker

    config = {"registry": {"mode": "distributed"}, "redis": {"url": "redis://localhost:6379/0"}}
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    w = DeviceWorker(worker_id="w1", config=config, redis_client=r)
    w._backend = MemoryRegistryBackend()  # see docs/testing-gaps.md TG-6
    w._retry_policy = RetryPolicy()
    await w._backend.set_device("up1", DeviceConfig(hostname="up1", base_url="http://up1/mcp", upstream_kind="mcp"))

    async def _fetch(_cfg):
        return {"upstream_kind": "mcp", "tools": TOOLS_V1}

    w._fetch_spec = _fetch  # type: ignore[method-assign]
    try:
        await w._spawn_pod("up1")
        stored = await w._backend.get_device("up1")
        assert stored.spec_hash == canonical_tools_hash(TOOLS_V1)
    finally:
        await w._kill_pod("up1")


# --- the fingerprint helper itself -------------------------------------------


def test_the_fingerprint_matches_what_the_registry_side_writes():
    """Embedded mode (SpecService) and distributed mode must agree on an OpenAPI spec's
    hash, or moving a device between modes reads as a spec change."""
    assert spec_fingerprint(SPEC_V1, is_proxy=False) == hashlib.sha256(str(SPEC_V1).encode()).hexdigest()[:16]


def test_the_fingerprint_uses_canonical_hashing_for_proxies():
    spec = {"upstream_kind": "mcp", "tools": TOOLS_V1}
    assert spec_fingerprint(spec, is_proxy=True) == canonical_tools_hash(TOOLS_V1)
