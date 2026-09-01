"""ADR-0022's routes must not be reachable on a default stack (unmounted 2026-09-01).

Unmounted, not deleted: the design stands and the code is still built and tested. What was
wrong was the shipping — it went live before it was finished.

Four reasons it came down, any one of which was sufficient:

* **LR-58.** `RedisPendingProposalStore` writes the plan as plain JSON, so a register plan puts
  `auth.api_key`/`client_secret` into Redis in the clear — the exact thing `main.py` refuses to
  start rather than let `register_device` do.
* **No consumer at either end.** Nothing calls these routes: no proposer, no reviewer.
* **Review cannot happen through this interface**: no list route (so a reviewer cannot discover
  a proposal at all) and no reject route.
* Lite and single-tenant are the supported editions; this was pure surface on both.

This file is the guard. Re-mounting requires deleting a test that states the re-entry
conditions, which is the point — remounting first and fixing after is the sequencing that
produced LR-58.
"""

from __future__ import annotations

import itertools

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ADMIN_KEY = "test-admin-key-0001"
_STACK_SEQ = itertools.count()

#: Every route ADR-0022 defines, with a body good enough to get past FastAPI's own parsing —
#: so a 404 here means "not mounted", never "malformed request".
PLAN_ROUTES = [
    ("post", "/v1/devices/plans", {"intent": "register", "hostname": "a", "base_url": "https://127.0.0.1:9"}),
    ("get", "/v1/devices/plans/some-proposal-id", None),
    ("post", "/v1/devices/plans/some-proposal-id/approve", {}),
    ("post", "/v1/devices/plans/apply", {"intent": "register", "hostname": "a"}),
]


def _client(monkeypatch, tmp_path, **kwargs):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setenv("MCP_SECRET_KEY", Fernet.generate_key().decode())
    from device_mcp_gateway.main import create_app

    return TestClient(create_app(**kwargs))


@pytest.mark.parametrize("method,path,body", PLAN_ROUTES, ids=[r[1] for r in PLAN_ROUTES])
def test_the_plan_routes_are_absent_by_default(monkeypatch, tmp_path, method, path, body):
    client = _client(monkeypatch, tmp_path)
    resp = getattr(client, method)(
        path, headers={"Authorization": f"Bearer {ADMIN_KEY}"}, **({"json": body} if body is not None else {})
    )
    # Absent, as an authenticated admin — not refused. 405 counts as absent and is the honest
    # answer for `POST /v1/devices/plans`: that PATH still exists as `/devices/{hostname}`
    # (GET/PUT/DELETE), so FastAPI reports the method missing rather than the path.
    assert resp.status_code in (404, 405), f"{method.upper()} {path} answered {resp.status_code}"


def test_a_future_list_route_would_be_shadowed_by_the_device_route(monkeypatch, tmp_path):
    """A landmine for re-entry condition 2, found by the assertion above answering 405.

    `/devices/plans` lives inside `/devices/{hostname}`'s path space, and `api_devices.router`
    is included first, so a list route added at `GET /v1/devices/plans` would never be reached
    — `GET /devices/{hostname}` matches first and answers "no such device 'plans'". The
    reviewer's inbox would 404 with a message about a device nobody asked for.

    Asserted rather than left as a comment: this is exactly the shape of thing that gets
    rediscovered by hand later. The list route belongs somewhere that does not collide, or the
    device route needs an explicit exclusion.
    """
    client = _client(monkeypatch, tmp_path, enable_write_planned=True)
    resp = client.get("/v1/devices/plans", headers={"Authorization": f"Bearer {ADMIN_KEY}"})
    assert resp.status_code == 404
    # The device route answered, not a plan route — that is the collision, stated as evidence.
    assert "plans" in resp.text and "evice" in resp.text, resp.text


def test_the_proposal_store_is_absent_by_default(monkeypatch, tmp_path):
    """No routes means no store. LR-58 is a property of the store existing and being written
    to, so a default stack must not carry one waiting to be filled."""
    client = _client(monkeypatch, tmp_path)
    assert getattr(client.app.state, "write_planned_proposals", None) is None
    assert getattr(client.app.state, "write_planned_grants", None) is None


def test_the_opt_in_still_wires_the_whole_thing(monkeypatch, tmp_path):
    """The other half: frozen must not mean rotted. The opt-in the route tests use has to
    produce the real wiring — authentication included, not a bare router."""
    client = _client(monkeypatch, tmp_path, enable_write_planned=True)
    resp = client.post(
        "/v1/devices/plans", json={"intent": "register", "hostname": "a", "base_url": "https://x.example"}
    )
    # 401/403, never 404: mounted, and behind `authenticate_request` like every other route.
    assert resp.status_code in (401, 403), resp.status_code
    assert client.app.state.write_planned_proposals is not None
