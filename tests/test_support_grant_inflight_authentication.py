# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §8, end-to-end — revoking a support grant interrupts a call already in flight.

`test_support_grant_inflight.py` proves the registry and the dependency function in isolation;
this proves the real wiring in `main.py` (`authenticate_request` -> `track_support_grant_inflight`
-> a real route) actually cancels a real in-flight request on the same process when the grant it
authenticated with is revoked mid-call — the property the whole slice exists for.
"""

from __future__ import annotations

import asyncio
import itertools

import httpx
import pytest

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40


def _make_app(monkeypatch, tmp_path):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    return create_app()


def _admin():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


async def _grant_a_support_credential(client: httpx.AsyncClient, *, scopes) -> str:
    raise_resp = await client.post(
        "/v1/support-requests",
        headers=_admin(),
        json={"provider_subject": "oidc:provider-idp#op1", "requested_scopes": scopes, "justification": "INC-1"},
    )
    request_id = raise_resp.json()["request_id"]
    await client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    poll = await client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )
    return poll.json()["credential"]


@pytest.mark.asyncio
async def test_a_support_grant_request_to_a_fast_route_is_unaffected(monkeypatch, tmp_path):
    """Regression: the new dependency must not interfere with the ordinary, uncancelled case."""
    app = _make_app(monkeypatch, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        credential = await _grant_a_support_credential(client, scopes=["devices:read"])
        resp = await client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_revoking_a_grant_cancels_a_call_already_in_flight_under_it(monkeypatch, tmp_path):
    app = _make_app(monkeypatch, tmp_path)
    transport = httpx.ASGITransport(app=app)

    started = asyncio.Event()

    async def _slow_list_devices():
        started.set()
        await asyncio.sleep(30)
        return []

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        credential = await _grant_a_support_credential(client, scopes=["devices:read"])
        monkeypatch.setattr(app.state.registry, "list_devices", _slow_list_devices)

        async def _slow_call():
            return await client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})

        async def _revoke_once_started():
            await started.wait()
            grants = (await client.get("/v1/support-grants", headers=_admin())).json()["grants"]
            grant_id = grants[0]["id"]
            resp = await client.delete(f"/v1/support-grants/{grant_id}", headers=_admin())
            assert resp.status_code == 204

        slow_task = asyncio.ensure_future(_slow_call())
        revoke_task = asyncio.ensure_future(_revoke_once_started())

        await revoke_task
        # The in-flight call was cancelled server-side (its task never reached `send` with a
        # response) rather than running to completion and returning 200 — confirmed by hand
        # against this exact ASGITransport/httpx pairing before being asserted here.
        with pytest.raises(RuntimeError, match="No response returned"):
            await slow_task

        # A brand-new call under the same (now-revoked) credential is refused outright.
        follow_up = await client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})
        assert follow_up.status_code == 401
