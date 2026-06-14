# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for the security-hardening batch (F-35 / F-36 / F-37).

F-35: body-size cap can't be bypassed by chunked / missing / understated Content-Length.
F-36: metrics exposition can require a bearer token.
F-37: a session is bound to the principal that opened it; another caller can't post to it.
"""

import socket
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager

import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

from device_mcp_gateway import metrics
from device_mcp_gateway.main import create_app
from device_mcp_gateway.rbac import Authenticator
from device_mcp_gateway.shared.registry_backend import DeviceConfig
from device_mcp_gateway.shared.session_router import SessionRouter

# ---------------------------------------------------------------------------
# F-35 — body-size guard
# ---------------------------------------------------------------------------


def _body_app(max_bytes, tmp_path):
    cfg = {
        "registry": {"mode": "embedded"},
        "storage": {"db_path": str(tmp_path / "d.db")},
        "metrics": {"enabled": False},
        "gateway": {"max_body_bytes": max_bytes},
    }
    return TestClient(create_app(override_config=cfg))


def test_declared_content_length_over_limit_rejected(tmp_path):
    client = _body_app(1024, tmp_path)
    # httpx sets Content-Length for a JSON body → the up-front header check rejects it.
    resp = client.post("/devices", json={"hostname": "x", "base_url": "http://192.0.2.1", "blob": "A" * 4000})
    assert resp.status_code == 413


def test_chunked_body_over_limit_rejected(tmp_path):
    client = _body_app(1024, tmp_path)

    def gen():
        for _ in range(8):
            yield b"A" * 512  # 4096 bytes total, sent chunked (no Content-Length)

    resp = client.post("/devices", content=gen())
    assert resp.status_code == 413  # caught by the streaming byte counter, not a header check


def test_small_body_under_limit_passes(tmp_path):
    client = _body_app(1_048_576, tmp_path)
    resp = client.post("/devices", json={"hostname": "ok", "base_url": "http://192.0.2.1", "auth_type": "none"})
    assert resp.status_code != 413  # registered (200) — body cap not triggered


# ---------------------------------------------------------------------------
# F-36 — metrics exposition auth
# ---------------------------------------------------------------------------


def test_metrics_token_resolution(monkeypatch):
    monkeypatch.delenv("MCP_METRICS_TOKEN", raising=False)
    assert metrics.metrics_token({"metrics": {"auth_token": "from-cfg"}}) == "from-cfg"
    assert metrics.metrics_token({"metrics": {}}) is None
    monkeypatch.setenv("MCP_METRICS_TOKEN", "from-env")
    assert metrics.metrics_token({"metrics": {"auth_token": "from-cfg"}}) == "from-env"  # env wins


def _free_port():
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until_listening(port, timeout=5.0):
    """Block until the metrics server thread is accepting connections, so the first
    request can't race the daemon thread's bind/listen (a CI flake otherwise)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.25)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise AssertionError(f"metrics server never started listening on :{port}")


def test_metrics_server_requires_bearer_token():
    port = _free_port()
    assert metrics.start_metrics_server(port, auth_token="sekret") is True
    _wait_until_listening(port)
    base = f"http://127.0.0.1:{port}/"

    # No token → 401.
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(base, timeout=3)
    assert exc.value.code == 401

    # Wrong token → 401.
    bad = urllib.request.Request(base, headers={"Authorization": "Bearer nope"})
    with pytest.raises(urllib.error.HTTPError) as exc2:
        urllib.request.urlopen(bad, timeout=3)
    assert exc2.value.code == 401

    # Correct token → 200 with exposition.
    good = urllib.request.Request(base, headers={"Authorization": "Bearer sekret"})
    with urllib.request.urlopen(good, timeout=3) as r:
        assert r.status == 200
        assert b"# HELP" in r.read()


# ---------------------------------------------------------------------------
# F-37 — principal ↔ session binding
# ---------------------------------------------------------------------------


class _SseRegistry:
    """Minimal registry: returns one pod-active SSE device for any hostname."""

    def __init__(self):
        self._device = DeviceConfig(
            hostname="dev", base_url="http://dev.local", transport="sse", reachable=True, pod_active=True
        )

    async def get_device(self, hostname):
        return self._device

    def get_profile(self, hostname):
        return None


def _sse_app(monkeypatch):
    cfg = {"registry": {"mode": "embedded"}, "metrics": {"enabled": False}}
    app = create_app(override_config=cfg)

    @asynccontextmanager
    async def _noop_lifespan(_app):
        yield

    app.router.lifespan_context = _noop_lifespan
    app.state.mode = "embedded"
    app.state.registry = _SseRegistry()
    monkeypatch.setattr(app.state, "authenticator", Authenticator({}, enabled=False))  # caller = "anonymous"
    return app


def test_messages_rejected_for_foreign_session(monkeypatch):
    app = _sse_app(monkeypatch)
    app.state.session_owners["sess-1"] = "key:someone-else"  # opened by another principal
    with TestClient(app) as client:
        resp = client.post(
            "/devices/dev/messages?session_id=sess-1",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert resp.status_code == 403
    assert "different principal" in resp.json()["detail"]


def test_messages_not_rejected_for_own_session(monkeypatch):
    app = _sse_app(monkeypatch)
    app.state.session_owners["sess-2"] = "anonymous"  # matches the ANONYMOUS caller
    with TestClient(app) as client:
        resp = client.post(
            "/devices/dev/messages?session_id=sess-2",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert resp.status_code != 403  # owner gate passed (downstream dispatch may differ)


def _owner_field(sess):
    # fakeredis returns bytes hash keys even with decode_responses=True; real Redis
    # (which the gateway runs with decode_responses) returns str. Read tolerantly.
    val = sess.get("owner", sess.get(b"owner"))
    return val.decode() if isinstance(val, bytes) else val


@pytest.mark.asyncio
async def test_session_router_stores_and_returns_owner():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    sr = SessionRouter(r)
    await sr.register("s1", "dev", "gw1", owner="key:alice")
    assert _owner_field(await sr.get("s1")) == "key:alice"
    # Without an owner the field is simply absent (backward compatible).
    await sr.register("s2", "dev", "gw1")
    assert _owner_field(await sr.get("s2")) is None
