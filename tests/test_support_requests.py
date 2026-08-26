# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017, slice 1 — the raise/poll/list/approve/reject/revoke/standing-consent API.
The store itself is covered by `test_support_grants.py`.

Properties that carry this slice:

1. **Every route needs `support:administer`.** `caller`'s baseline (no such scope) is refused.
2. **A poll is scoped to its own `provider_subject`** — the wrong one 404s exactly like the
   request never existed, never a different error that would leak its existence.
3. **`justification` is recorded in the audit chain and never echoed back** in any response.
4. **Standing consent is the same mechanism, only a different trigger**: a raise under a
   matching, active standing-consent setting is immediately deliverable on the very next poll.
5. **Revoke is idempotent** — a second revoke, or one against something already expired,
   still 204s.
6. **`/support-requests/standing-consent` is not swallowed by `/support-requests/{request_id}`**
   — the literal route must win, which requires it to be registered first.
"""

from __future__ import annotations

import itertools

from fastapi.testclient import TestClient

from device_mcp_gateway.rbac import (
    ALL_SCOPES,
    Principal,
    SCOPE_DEVICES_WRITE_PLANNED,
    SCOPE_SUPPORT_ADMINISTER,
    scopes_for_role,
)

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


RAISE_BODY = {
    "provider_subject": "oidc:provider-idp#op1",
    "requested_scopes": ["devices:read", "tools:call"],
    "justification": "ticket INC-9001",
}


def _raise(client, **overrides):
    return client.post("/v1/support-requests", headers=_admin(), json={**RAISE_BODY, **overrides})


# --- scope gating -----------------------------------------------------------------------


def test_admin_has_support_administer():
    assert SCOPE_SUPPORT_ADMINISTER in ALL_SCOPES
    assert SCOPE_SUPPORT_ADMINISTER in scopes_for_role("admin")


def test_raise_is_refused_without_support_administer(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/support-requests", headers=_no_scope(), json=RAISE_BODY)
    assert resp.status_code == 403


# --- raise --------------------------------------------------------------------------------


def test_raise_returns_expected_shape_without_echoing_justification(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _raise(client)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body.keys()) == {"request_id", "requested_scopes", "expires_at"}
    assert body["requested_scopes"] == ["devices:read", "tools:call"]
    assert isinstance(body["request_id"], str) and len(body["request_id"]) > 16


def test_raise_requires_provider_subject(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _raise(client, provider_subject="")
    assert resp.status_code == 400


def test_raise_requires_justification(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _raise(client, justification="")
    assert resp.status_code == 400


def test_raise_refuses_devices_write_planned_as_a_requested_scope(monkeypatch, tmp_path):
    """The one scope that must never be held via any standing/administered mechanism —
    ADR-0022's own rule, unchanged here."""
    client = _client(monkeypatch, tmp_path)
    resp = _raise(client, requested_scopes=[SCOPE_DEVICES_WRITE_PLANNED])
    assert resp.status_code == 400


def test_raise_refuses_support_administer_as_a_requested_scope(monkeypatch, tmp_path):
    """A support grant must not be able to mint the power to administer more support
    grants — that is privilege escalation, not a support session."""
    client = _client(monkeypatch, tmp_path)
    resp = _raise(client, requested_scopes=[SCOPE_SUPPORT_ADMINISTER])
    assert resp.status_code == 400


def test_raise_requires_a_json_object_body(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post(
        "/v1/support-requests", headers={**_admin(), "Content-Type": "application/json"}, content=b"not json"
    )
    assert resp.status_code == 400


# --- list pending ---------------------------------------------------------------------------


def test_list_pending_shows_a_freshly_raised_request(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]

    resp = client.get("/v1/support-requests", headers=_admin())

    assert resp.status_code == 200
    ids = [r["request_id"] for r in resp.json()["requests"]]
    assert ids == [request_id]
    # justification IS visible to a reviewer here — it's the tenant admin deciding, not an
    # external API response; only the *raise* response withholds it.
    assert resp.json()["requests"][0]["justification"] == "ticket INC-9001"


# --- poll: session-bound delivery -----------------------------------------------------------


def test_poll_reports_pending(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]

    resp = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "pending"}


def test_poll_from_the_wrong_subject_404s(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]

    resp = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "someone-else"}
    )

    assert resp.status_code == 404


def test_poll_an_unknown_request_id_404s(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/support-requests/never-created", headers=_admin(), params={"provider_subject": "op1"})
    assert resp.status_code == 404


# --- approve ------------------------------------------------------------------------------


def test_approve_mints_a_grant_delivered_on_the_next_poll(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]

    approve = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    assert approve.status_code == 200, approve.text
    grant_id = approve.json()["grant_id"]

    poll = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "approved"
    assert body["grant_id"] == grant_id
    assert body["credential"] == grant_id  # the grant's own id IS the bearer (see module docstring)


def test_approving_the_same_request_twice_404s_the_second_time(monkeypatch, tmp_path):
    """`get()` only ever sees a still-pending request, so a sequential re-decision reads as
    "no such pending request" — the 409 race-path (`test_a_request_cannot_be_decided_twice`
    in test_support_grants.py) is for the concurrent case, where both routes' `get()` still
    see it pending and race at the store's atomic decide instead."""
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]
    first = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    second = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    assert first.status_code == 200
    assert second.status_code == 404


def test_approving_an_unknown_request_404s(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/support-requests/never-created/approve", headers=_admin())
    assert resp.status_code == 404


def test_approve_ttl_is_capped_at_the_configured_ceiling(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]

    resp = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin(), json={"ttl_seconds": 10**9})

    assert resp.status_code == 200
    from device_mcp_gateway.cfg import support_grant_ttl_seconds

    ceiling = support_grant_ttl_seconds({})
    assert resp.json()["expires_at"] <= resp.json()["expires_at"]  # sanity: present
    # The grant's own expiry must not exceed roughly now + ceiling.
    import time

    assert resp.json()["expires_at"] <= time.time() + ceiling + 5


# --- reject -------------------------------------------------------------------------------


def test_reject_delivers_rejected_on_the_next_poll(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]

    reject = client.post(f"/v1/support-requests/{request_id}/reject", headers=_admin())
    assert reject.status_code == 204

    poll = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )
    assert poll.json() == {"status": "rejected"}


def test_rejecting_twice_404s_the_second_time(monkeypatch, tmp_path):
    """Same reasoning as the approve case above."""
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]
    first = client.post(f"/v1/support-requests/{request_id}/reject", headers=_admin())
    second = client.post(f"/v1/support-requests/{request_id}/reject", headers=_admin())
    assert first.status_code == 204
    assert second.status_code == 404


# --- list active grants + revoke --------------------------------------------------------------


def test_list_active_grants_shows_an_approved_grant(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]
    grant_id = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin()).json()["grant_id"]

    resp = client.get("/v1/support-grants", headers=_admin())

    assert resp.status_code == 200
    ids = [g["id"] for g in resp.json()["grants"]]
    assert ids == [grant_id]
    assert resp.json()["grants"][0]["provider_subject"] == "oidc:provider-idp#op1"


def test_revoke_removes_it_from_the_active_list(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]
    grant_id = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin()).json()["grant_id"]

    revoke = client.delete(f"/v1/support-grants/{grant_id}", headers=_admin())
    listed = client.get("/v1/support-grants", headers=_admin())

    assert revoke.status_code == 204
    assert listed.json()["grants"] == []


def test_revoking_twice_is_still_204(monkeypatch, tmp_path):
    """The whole point: a tenant admin clicking revoke a second time must never see an
    error."""
    client = _client(monkeypatch, tmp_path)
    request_id = _raise(client).json()["request_id"]
    grant_id = client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin()).json()["grant_id"]
    first = client.delete(f"/v1/support-grants/{grant_id}", headers=_admin())
    second = client.delete(f"/v1/support-grants/{grant_id}", headers=_admin())
    assert (first.status_code, second.status_code) == (204, 204)


def test_revoking_an_unknown_grant_404s(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.delete("/v1/support-grants/never-issued", headers=_admin())
    assert resp.status_code == 404


# --- standing consent -----------------------------------------------------------------------


def test_standing_consent_route_is_not_swallowed_by_the_request_id_route(monkeypatch, tmp_path):
    """The regression this ordering exists to prevent: without registering the literal route
    first, this GET would 404 as if "standing-consent" were an unknown request id."""
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/support-requests/standing-consent", headers=_admin())
    assert resp.status_code == 200
    assert resp.json() == {"enabled": False}


def test_enabling_standing_consent_round_trips(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/support-requests/standing-consent", headers=_admin(), json={"scopes": ["devices:read"]})
    assert resp.status_code == 201

    consent = client.get("/v1/support-requests/standing-consent", headers=_admin()).json()
    assert consent["enabled"] is True
    assert consent["scopes"] == ["devices:read"]


def test_disabling_standing_consent(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    client.post("/v1/support-requests/standing-consent", headers=_admin(), json={"scopes": ["devices:read"]})

    disable = client.delete("/v1/support-requests/standing-consent", headers=_admin())
    consent = client.get("/v1/support-requests/standing-consent", headers=_admin()).json()

    assert disable.status_code == 204
    assert consent == {"enabled": False}


def test_raise_under_standing_consent_is_immediately_deliverable(monkeypatch, tmp_path):
    """Not a different mechanism, only a different trigger (§3): the caller still raises,
    then polls — the same shape as the human-approval path — but the very first poll already
    sees "approved"."""
    client = _client(monkeypatch, tmp_path)
    client.post("/v1/support-requests/standing-consent", headers=_admin(), json={"scopes": ["devices:read"]})

    request_id = _raise(client, requested_scopes=["devices:read"]).json()["request_id"]
    poll = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )

    assert poll.json()["status"] == "approved"


def test_raise_under_standing_consent_still_returns_a_real_expires_at(monkeypatch, tmp_path):
    """Regression: `get()` only ever sees a still-pending request, so reading it again after
    the self-issue path already approved it would silently null this out."""
    client = _client(monkeypatch, tmp_path)
    client.post("/v1/support-requests/standing-consent", headers=_admin(), json={"scopes": ["devices:read"]})

    resp = _raise(client, requested_scopes=["devices:read"])

    assert resp.json()["expires_at"] is not None


def test_raise_exceeding_standing_consent_scopes_still_goes_pending(monkeypatch, tmp_path):
    """Standing consent only fast-tracks requests it actually covers — asking for more than
    it grants still needs a human decision."""
    client = _client(monkeypatch, tmp_path)
    client.post("/v1/support-requests/standing-consent", headers=_admin(), json={"scopes": ["devices:read"]})

    request_id = _raise(client, requested_scopes=["devices:read", "tools:call"]).json()["request_id"]
    poll = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )

    assert poll.json()["status"] == "pending"


def test_standing_consent_requires_scopes(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/support-requests/standing-consent", headers=_admin(), json={})
    assert resp.status_code == 400
