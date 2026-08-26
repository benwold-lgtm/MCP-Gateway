# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017, slice 2 — a live support grant authenticates a request end-to-end.

Slices 0/1 built and tested the store and the API that mints a grant; this proves the OTHER
half — that the grant's own id, presented as a bearer, actually gets a caller through
`authenticate_request` and onto a real route, with exactly the scopes the grant carries, and
that revocation (checked live, not once at redemption — the whole reason no separate signed
token was built) takes effect on the very next request.
"""

from __future__ import annotations

import itertools

import pytest
from fastapi.testclient import TestClient
from loguru import logger

from device_mcp_gateway.rbac import Principal, scopes_for_role

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40


def _client(monkeypatch, tmp_path):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    return TestClient(create_app())


def _admin():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _grant_a_support_credential(client, *, scopes) -> str:
    """Raise + approve, exactly the flow a real provider operator/tenant admin pair follows,
    and return the delivered bearer — never construct a grant id by hand."""
    raise_resp = client.post(
        "/v1/support-requests",
        headers=_admin(),
        json={"provider_subject": "oidc:provider-idp#op1", "requested_scopes": scopes, "justification": "INC-1"},
    )
    request_id = raise_resp.json()["request_id"]
    client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    poll = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )
    return poll.json()["credential"]


def test_a_support_grant_bearer_authenticates_and_carries_exactly_its_scopes(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    credential = _grant_a_support_credential(client, scopes=["devices:read"])

    resp = client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})

    assert resp.status_code == 200, resp.text


def test_a_support_grant_bearer_is_refused_for_a_scope_it_does_not_carry(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    credential = _grant_a_support_credential(client, scopes=["devices:read"])  # no devices:write

    resp = client.post(
        "/v1/devices",
        headers={"Authorization": f"Bearer {credential}"},
        json={"hostname": "sensor-1", "base_url": "http://sensor-1.example/"},
    )

    assert resp.status_code == 403


def test_the_resolved_principal_is_the_provider_operator_never_a_shared_identity(monkeypatch, tmp_path):
    """The property ADR-0017 §7 calls out as needing testing, not just asserting: the
    subject authenticated via the grant must be the operator's own identity, not something
    generic like "support" or the tenant admin who approved it."""
    client = _client(monkeypatch, tmp_path)
    credential = _grant_a_support_credential(client, scopes=["devices:read"])

    resp = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {credential}"})

    assert resp.status_code == 200
    assert resp.json()["subject"] == "oidc:provider-idp#op1"
    assert resp.json()["auth_method"] == "support_grant"


def test_revoking_a_grant_refuses_the_very_next_request(monkeypatch, tmp_path):
    """The property the whole "no separate signed token" design rests on: revocation is
    checked live, not once at some earlier point."""
    client = _client(monkeypatch, tmp_path)
    credential = _grant_a_support_credential(client, scopes=["devices:read"])
    assert client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"}).status_code == 200

    grants = client.get("/v1/support-grants", headers=_admin()).json()["grants"]
    grant_id = grants[0]["id"]
    revoke = client.delete(f"/v1/support-grants/{grant_id}", headers=_admin())
    assert revoke.status_code == 204

    resp = client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})
    assert resp.status_code == 401


def test_a_garbage_bearer_that_merely_looks_like_a_support_grant_token_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/devices", headers={"Authorization": "Bearer sgr_totally-made-up"})
    assert resp.status_code == 401


def test_an_ordinary_static_key_is_unaffected_by_the_new_fallback(monkeypatch, tmp_path):
    """The fallback must never shadow or interfere with the existing static-key path."""
    client = _client(monkeypatch, tmp_path)
    resp = client.get("/v1/devices", headers=_admin())
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_a_support_grant_principal_is_not_break_glass():
    """Confirms the new path never accidentally trips the break-glass notification — a
    support grant is the opposite of an emergency unilateral path. `WhoAmIResponse` doesn't
    expose `break_glass` at all, so this checks the resolver directly rather than through
    a route that couldn't show a regression here either way."""
    from types import SimpleNamespace

    from device_mcp_gateway.rbac import _support_grant_principal
    from device_mcp_gateway.support_grants import InMemorySupportGrantStore

    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=frozenset({"devices:read"}), ttl_seconds=60)
    fake_request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(support_grants=store)))

    principal = await _support_grant_principal(fake_request, grant.id)

    assert principal is not None
    assert principal.break_glass is False


def test_scopes_for_role_admin_is_unaffected():
    """Sanity: the new Principal field defaults to None and does not disturb the existing
    role/scope machinery this module already depends on."""
    p = Principal(subject="key:admin", scopes=scopes_for_role("admin"), auth_method="api_key")
    assert p.support_grant_id is None


# --- slice 5: routine per-use attribution -------------------------------------------------
#
# Not a pytest fixture: `create_app()` (called from `_client`) runs `setup_logging`, which
# calls `logger.remove()` and would silently tear down a sink added beforehand — so the sink
# is added only after the app (and its logging) already exists.


class _audit_log:
    def __enter__(self):
        self.records: list[dict] = []

        def _sink(message):
            rec = message.record
            if rec["extra"].get("event") == "audit":
                self.records.append(rec["extra"])

        self._sink_id = logger.add(_sink, level="INFO")
        return self.records

    def __exit__(self, *exc):
        logger.remove(self._sink_id)


def _of(records, action):
    return [r for r in records if r.get("action") == action]


def test_every_use_emits_a_support_grant_use_event(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    credential = _grant_a_support_credential(client, scopes=["devices:read"])

    with _audit_log() as audit_log:
        client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})
        client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})

    uses = _of(audit_log, "support_grant.use")
    assert len(uses) == 2
    assert uses[0]["subject"] == "oidc:provider-idp#op1"
    assert uses[0]["tier"] == "tier0"


def test_a_refused_call_never_emits_a_use_event(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    credential = _grant_a_support_credential(client, scopes=["devices:read"])
    grants = client.get("/v1/support-grants", headers=_admin()).json()["grants"]
    client.delete(f"/v1/support-grants/{grants[0]['id']}", headers=_admin())

    with _audit_log() as audit_log:
        client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})  # now 401s

    assert _of(audit_log, "support_grant.use") == []
