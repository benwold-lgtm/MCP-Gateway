# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Distributed-mode tests for the fleet MCP endpoint (Phase 2).

Mirrors test_admission_control.py's pattern: a stubbed Registry/backend over a
real fakeredis client, with the distributed lifespan replaced by a no-op so no
real Redis/worker is required. Covers what's specific to distributed mode: the
fleet tools lookup table surviving a cross-replica read, the admission-control
(F-06) and timeout-watcher (F6) sequence being reused for fleet tools/call, and
one overloaded/dead device not affecting other devices in the same session.
"""

import asyncio
import copy
from contextlib import asynccontextmanager

import fakeredis.aioredis
import yaml
from fastapi.testclient import TestClient

from device_mcp_gateway.core.errors import RPC_METHOD_NOT_FOUND
from device_mcp_gateway.main import create_app
from device_mcp_gateway.rbac import Authenticator
from device_mcp_gateway.shared.registry_backend import DeviceConfig
from device_mcp_gateway.shared.session_router import SessionRouter


def _fake_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _tool(name, description="d", schema=None):
    return {"name": name, "description": description, "schema": schema or {}}


class _FleetStubBackend:
    def __init__(self, backlog_by_host: dict | None = None):
        self._backlog_by_host = backlog_by_host or {}
        self.published: list[dict] = []

    async def call_backlog(self, hostname: str) -> int:
        return self._backlog_by_host.get(hostname, 0)

    async def publish_tool_call(self, **kwargs):
        self.published.append(kwargs)


class _FleetStubRegistry:
    def __init__(self, devices: dict, manifests: dict, backend):
        self._devices = devices  # hostname -> pod_active bool
        self._manifests = manifests
        self._backend = backend

    async def get_device(self, hostname):
        active = self._devices.get(hostname)
        if active is None:
            return None
        return DeviceConfig(hostname=hostname, base_url=f"http://{hostname}", pod_active=active, transport="sse")

    async def get_manifest(self, hostname):
        return self._manifests.get(hostname)


def _distributed_fleet_app(devices, manifests, backlog_by_host, monkeypatch):
    cfg = copy.deepcopy(yaml.safe_load(open("config.yaml")))
    cfg.setdefault("registry", {})
    cfg["registry"]["mode"] = "distributed"
    cfg["registry"]["call_backlog_limit"] = 1000
    cfg.setdefault("gateway", {})["allow_plaintext_credentials"] = True
    cfg["gateway"]["allow_anonymous"] = True
    cfg.setdefault("redis", {})["allow_insecure"] = True
    app = create_app(override_config=cfg)

    @asynccontextmanager
    async def _noop_lifespan(_app):
        yield

    app.router.lifespan_context = _noop_lifespan
    backend = _FleetStubBackend(backlog_by_host)
    redis = _fake_redis()
    app.state.redis = redis
    app.state.session_router = SessionRouter(redis)
    app.state.registry = _FleetStubRegistry(devices, manifests, backend)
    monkeypatch.setattr(app.state, "authenticator", Authenticator({}, enabled=False))
    return app, backend


# Note: GET /v1/fleet/sse's distributed branch (register + set_fleet_tools before
# the first SSE yield) is deliberately not exercised end-to-end here. Neither does
# the pre-existing per-device GET /devices/{hostname}/sse in distributed mode --
# test_admission_control.py only ever drives the POST /messages route, and the
# project's real-Redis tier (test_integration_redis.py) tests SessionRouter/backend
# directly rather than through a live streaming HTTP request, for the same reason:
# a fakeredis-backed single-threaded event loop and an infinite SSE generator
# (blocking XREAD) don't combine reliably under TestClient or a background-thread
# uvicorn server -- confirmed flaky when attempted here. The distributed-specific
# behavior that matters (the lookup table surviving a cross-replica read) is
# covered below against fakeredis, and against real Redis in
# test_integration_redis.py::test_fleet_tools_roundtrip_and_cross_client_visibility.


# --- POST /v1/fleet/messages: cross-replica read of the fleet tools table ----


def _seed_session(app, session_id, owner, tools):
    session_router: SessionRouter = app.state.session_router

    async def _seed():
        await session_router.register(session_id, "", "gw-a", owner=owner)
        await session_router.set_fleet_tools(session_id, tools)

    asyncio.run(_seed())


def test_fleet_messages_reads_tools_written_by_a_different_router_instance(monkeypatch):
    """The GET may be served by a different gateway replica than the POST --
    simulate that by seeding state through a second SessionRouter instance
    sharing the same (fake) Redis, not the one the app itself holds."""
    devices = {"a": True}
    manifests = {"a": {"tools": [_tool("get_status")]}}
    app, backend = _distributed_fleet_app(devices, manifests, {}, monkeypatch)

    other_router = SessionRouter(app.state.redis)

    async def _seed_other():
        await other_router.register("s1", "", "gw-b", owner=None)
        await other_router.set_fleet_tools("s1", {"a_get_status": {"hostname": "a", "real_name": "get_status"}})

    asyncio.run(_seed_other())

    with TestClient(app) as client:
        resp = client.post(
            "/v1/fleet/messages?session_id=s1",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert resp.status_code == 200
    assert resp.json()["result"]["tools"][0]["name"] == "a_get_status"


def test_fleet_messages_tools_call_dispatches_via_publish_tool_call(monkeypatch):
    devices = {"a": True}
    manifests = {"a": {"tools": [_tool("get_status")]}}
    app, backend = _distributed_fleet_app(devices, manifests, {}, monkeypatch)
    _seed_session(app, "s2", None, {"a_get_status": {"hostname": "a", "real_name": "get_status"}})

    with TestClient(app) as client:
        resp = client.post(
            "/v1/fleet/messages?session_id=s2",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "a_get_status", "arguments": {}},
            },
        )
    assert resp.status_code == 200
    assert resp.json() == {"status": "accepted"}
    assert len(backend.published) == 1
    assert backend.published[0]["hostname"] == "a"
    # the device receives the call under its own (unprefixed) tool name
    assert backend.published[0]["message"]["params"]["name"] == "get_status"


def test_fleet_messages_unknown_tool_name_returns_rpc_error_without_publishing(monkeypatch):
    devices = {"a": True}
    manifests = {"a": {"tools": [_tool("get_status")]}}
    app, backend = _distributed_fleet_app(devices, manifests, {}, monkeypatch)
    _seed_session(app, "s3", None, {"a_get_status": {"hostname": "a", "real_name": "get_status"}})

    with TestClient(app) as client:
        resp = client.post(
            "/v1/fleet/messages?session_id=s3",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"]["code"] == RPC_METHOD_NOT_FOUND
    assert backend.published == []


def test_fleet_messages_unknown_session_returns_404(monkeypatch):
    app, _ = _distributed_fleet_app({}, {}, {}, monkeypatch)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/fleet/messages?session_id=ghost",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert resp.status_code == 404


def test_fleet_messages_owner_mismatch_returns_403(monkeypatch):
    app, _ = _distributed_fleet_app({"a": True}, {"a": {"tools": [_tool("get_status")]}}, {}, monkeypatch)
    _seed_session(app, "s4", "someone-else", {"a_get_status": {"hostname": "a", "real_name": "get_status"}})

    with TestClient(app) as client:
        resp = client.post(
            "/v1/fleet/messages?session_id=s4",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert resp.status_code == 403


# --- Isolation: one overloaded/unknown device doesn't affect the rest --------


def test_fleet_messages_backlog_shed_isolated_to_one_device(monkeypatch):
    """One overloaded device in a fleet session sheds with 429; a call to a
    different, healthy device in the *same* session still succeeds."""
    devices = {"busy": True, "healthy": True}
    manifests = {
        "busy": {"tools": [_tool("get_status")]},
        "healthy": {"tools": [_tool("get_status")]},
    }
    app, backend = _distributed_fleet_app(devices, manifests, {"busy": 5}, monkeypatch)
    app.state.registry._backend._backlog_by_host = {"busy": 9999}  # over the 1000 watermark
    _seed_session(
        app,
        "s5",
        None,
        {
            "busy_get_status": {"hostname": "busy", "real_name": "get_status"},
            "healthy_get_status": {"hostname": "healthy", "real_name": "get_status"},
        },
    )

    with TestClient(app) as client:
        busy_resp = client.post(
            "/v1/fleet/messages?session_id=s5",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "busy_get_status", "arguments": {}},
            },
        )
        healthy_resp = client.post(
            "/v1/fleet/messages?session_id=s5",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "healthy_get_status", "arguments": {}},
            },
        )

    assert busy_resp.status_code == 429
    assert healthy_resp.status_code == 200
    assert healthy_resp.json() == {"status": "accepted"}
    assert len(backend.published) == 1
    assert backend.published[0]["hostname"] == "healthy"


# --- No changes needed to worker/runner.py: a fleet session_id is just another
# session_id to publish_result / subscribe, verified at the SessionRouter layer
# already in test_session_router.py (test_fleet_tools_visible_across_router_instances_on_same_redis).
