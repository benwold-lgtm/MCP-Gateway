# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 slice 5 — `GET /v1/notifications`, the read-only tenant-notification surface.

Gated by `notifications:read`, a scope distinct from `support:administer`: reading this list is
passive fleet visibility, not administering the support mechanism. The two real producers
(break-glass activation, standing-consent self-issue frequency) are proven end-to-end in
`test_break_glass_activity.py` and `test_support_requests.py`; this is the route in isolation.
"""

from __future__ import annotations

import itertools

from fastapi.testclient import TestClient

from device_mcp_gateway.rbac import Principal

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40
NO_SCOPE_KEY = "n" * 40


def _client(monkeypatch, tmp_path):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    client = TestClient(create_app())
    client.app.state.authenticator._keys[NO_SCOPE_KEY] = Principal(
        subject="key:nobody", scopes=frozenset(), auth_method="api_key"
    )
    return client


def _admin():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _no_scope():
    return {"Authorization": f"Bearer {NO_SCOPE_KEY}"}


def test_requires_notifications_read(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/notifications", headers=_no_scope())
    assert resp.status_code == 403


def test_an_empty_stack_has_no_notifications(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/notifications", headers=_admin())
    assert resp.status_code == 200
    assert resp.json() == {"notifications": []}


def test_lists_a_created_notification(monkeypatch, tmp_path):
    import asyncio

    client = _client(monkeypatch, tmp_path)
    asyncio.run(
        client.app.state.tenant_notifications.create(
            kind="break_glass.activated", subject="key:alice", message="m", severity="critical"
        )
    )

    resp = client.get("/v1/notifications", headers=_admin())
    [only] = resp.json()["notifications"]
    assert only["kind"] == "break_glass.activated"
    assert only["subject"] == "key:alice"
    assert only["severity"] == "critical"


def test_newest_first(monkeypatch, tmp_path):
    import asyncio

    client = _client(monkeypatch, tmp_path)

    async def _seed():
        store = client.app.state.tenant_notifications
        await store.create(kind="k", subject="s", message="first", severity="warning")
        await store.create(kind="k", subject="s", message="second", severity="warning")

    asyncio.run(_seed())

    resp = client.get("/v1/notifications", headers=_admin())
    messages = [n["message"] for n in resp.json()["notifications"]]
    assert messages == ["second", "first"]


def test_limit_is_respected(monkeypatch, tmp_path):
    import asyncio

    client = _client(monkeypatch, tmp_path)

    async def _seed():
        store = client.app.state.tenant_notifications
        for i in range(5):
            await store.create(kind="k", subject="s", message=str(i), severity="warning")

    asyncio.run(_seed())

    resp = client.get("/v1/notifications", headers=_admin(), params={"limit": 2})
    assert len(resp.json()["notifications"]) == 2


def test_limit_out_of_range_is_rejected(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/notifications", headers=_admin(), params={"limit": 0})
    assert resp.status_code == 422
    resp = client.get("/v1/notifications", headers=_admin(), params={"limit": 201})
    assert resp.status_code == 422
