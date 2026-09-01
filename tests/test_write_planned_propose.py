# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0022, slice 3 — Propose. Route-level tests; the store itself is covered by
`test_write_planned.py`.

Two properties carry this slice, and each has a test that fails if it regresses:

1. **Propose reaches nothing and validates nothing beyond shape.** The ADR spends a whole
   paragraph on why: allowing Propose to probe a candidate target — even indirectly, via
   the SSRF guard's own structural check — would be an unprivileged side door to the exact
   thing `devices:write` exists to gate. `test_propose_never_invokes_the_ssrf_guard`
   proves this by making the guard itself explode and confirming Propose does not care.
2. **The digest Propose returns is recomputable from the request body alone**, with no
   hidden normalization — `compute_digest(body) == response["plan_digest"]` — because
   slice 5's Apply has to reproduce it independently from its own freshly-parsed request.
   Anything Propose does to the body before hashing that Apply doesn't also do breaks the
   whole mechanism silently: every apply would 409 as `ERR_PLAN_STALE`-shaped, or worse,
   collide by accident.
"""

from __future__ import annotations

import itertools

import pytest
from fastapi.testclient import TestClient

from loguru import logger

from device_mcp_gateway.rbac import Principal, SCOPE_DEVICES_READ, SCOPE_TOOLS_CALL, scopes_for_role
from device_mcp_gateway.shared.canonical_json import compute_digest

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40
CALLER_KEY = "c" * 40
NO_SCOPE_KEY = "n" * 40


def _client(monkeypatch, tmp_path):
    # Same isolation as test_backup_restore.py's `_client`: embedded mode persists to the
    # relative `storage.db_path` by default, so without a chdir every test here writes into
    # the repo's own working directory.
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    client = TestClient(create_app(enable_write_planned=True))
    client.app.state.authenticator._keys[CALLER_KEY] = Principal(
        subject="key:agent1", scopes=scopes_for_role("caller"), auth_method="api_key"
    )
    client.app.state.authenticator._keys[NO_SCOPE_KEY] = Principal(
        subject="key:nobody", scopes=frozenset(), auth_method="api_key"
    )
    return client


def _admin():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _caller():
    return {"Authorization": f"Bearer {CALLER_KEY}"}


def _no_scope():
    return {"Authorization": f"Bearer {NO_SCOPE_KEY}"}


PLAN = {"intent": "register", "hostname": "sensor-1", "base_url": "http://sensor-1.example/"}


def _propose(client, headers, **body):
    payload = {**PLAN, **body}
    return client.post("/v1/devices/plans", headers=headers, json=payload)


# --- scope: caller's existing baseline is enough, nothing new required ---------------------


def test_propose_succeeds_for_a_caller_scoped_principal(monkeypatch, tmp_path):
    """`caller`'s baseline (`devices:read` + `tools:call`) is unchanged by this ADR — this
    pins that Propose needs nothing more."""
    client = _client(monkeypatch, tmp_path)
    assert SCOPE_DEVICES_READ in scopes_for_role("caller")
    assert SCOPE_TOOLS_CALL in scopes_for_role("caller")

    resp = _propose(client, _caller())

    assert resp.status_code == 200, resp.text


def test_propose_is_refused_without_devices_read(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _propose(client, _no_scope())
    assert resp.status_code == 403


# --- shape validation, and only shape validation ---------------------------------------------


def test_a_well_formed_register_proposal_returns_the_expected_shape(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _propose(client, _admin())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"proposal_id", "plan", "plan_digest", "expires_at"}
    assert body["plan"] == PLAN
    assert isinstance(body["proposal_id"], str) and len(body["proposal_id"]) > 16
    assert isinstance(body["plan_digest"], str) and len(body["plan_digest"]) == 64  # SHA-256 hex


def test_a_non_json_body_is_a_400(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post(
        "/v1/devices/plans", headers={**_admin(), "Content-Type": "application/json"}, content=b"not json"
    )
    assert resp.status_code == 400


def test_a_non_object_body_is_a_400(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/devices/plans", headers=_admin(), json=["not", "an", "object"])
    assert resp.status_code == 400


def test_missing_intent_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/devices/plans", headers=_admin(), json={"hostname": "sensor-1", "base_url": "http://x/"})
    assert resp.status_code == 400
    assert "intent" in resp.json()["detail"]


def test_unknown_intent_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _propose(client, _admin(), intent="delete")
    assert resp.status_code == 400
    assert "intent" in resp.json()["detail"]


def test_missing_hostname_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/devices/plans", headers=_admin(), json={"intent": "register", "base_url": "http://x/"})
    assert resp.status_code == 400
    assert "hostname" in resp.json()["detail"]


def test_register_without_base_url_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/devices/plans", headers=_admin(), json={"intent": "register", "hostname": "sensor-1"})
    assert resp.status_code == 400
    assert "base_url" in resp.json()["detail"]


def test_an_update_proposal_does_not_require_base_url(monkeypatch, tmp_path):
    """Reconfiguring an existing device may only touch, say, `rate_limit_rps` — `base_url`
    is register's requirement, not update's."""
    client = _client(monkeypatch, tmp_path)
    resp = client.post(
        "/v1/devices/plans", headers=_admin(), json={"intent": "update", "hostname": "sensor-1", "rate_limit_rps": 2}
    )
    assert resp.status_code == 200, resp.text


# --- the load-bearing restriction: Propose reaches nothing ------------------------------------


def test_propose_never_invokes_the_ssrf_guard(monkeypatch, tmp_path):
    """The ADR's own words: allowing Propose to reach the SSRF guard, even just its
    structural check, is an unprivileged side door to the thing `devices:write` gates.
    Making the guard explode and confirming Propose does not care is a stronger proof than
    asserting no network call happened — it proves the *code path* is never reached, not
    merely that this particular target didn't trigger one."""
    import device_mcp_gateway.security.url_policy as url_policy

    def _boom(*a, **kw):
        raise AssertionError("the SSRF guard must never be invoked during Propose")

    monkeypatch.setattr(url_policy, "validate_target_url", _boom)
    client = _client(monkeypatch, tmp_path)

    resp = _propose(client, _admin(), base_url="http://169.254.169.254/latest/meta-data/")

    assert resp.status_code == 200, resp.text


def test_propose_does_not_touch_the_registry(monkeypatch, tmp_path):
    """No device is registered, updated, or even read by name — Propose only writes to the
    proposal store."""
    client = _client(monkeypatch, tmp_path)
    _propose(client, _admin())
    assert client.get("/v1/devices", headers=_admin()).json()["devices"] == []


# --- the digest is recomputable, with no hidden normalization ---------------------------------


def test_the_returned_digest_matches_an_independent_computation(monkeypatch, tmp_path):
    """The property slice 5's Apply depends on: recomputing `compute_digest` on the same
    body, independently, from a different call site, must agree exactly."""
    client = _client(monkeypatch, tmp_path)
    resp = _propose(client, _admin())
    assert compute_digest(PLAN) == resp.json()["plan_digest"]


def test_identical_bodies_always_produce_the_same_digest(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    first = _propose(client, _admin()).json()["plan_digest"]
    second = _propose(client, _admin()).json()["plan_digest"]
    assert first == second


def test_different_bodies_produce_different_digests(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    a = _propose(client, _admin(), hostname="sensor-1").json()["plan_digest"]
    b = _propose(client, _admin(), hostname="sensor-2").json()["plan_digest"]
    assert a != b


# --- the proposal actually lands in the store, for the reviewer to read later -----------------


@pytest.mark.asyncio
async def test_the_proposal_is_retrievable_from_the_store_by_its_id(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _propose(client, _caller())
    body = resp.json()

    store = client.app.state.write_planned_proposals
    stored = await store.get(body["proposal_id"])

    assert stored is not None
    assert stored.subject == "key:agent1"
    assert stored.digest == body["plan_digest"]
    assert stored.plan == PLAN


def test_expires_at_reflects_the_configured_ttl(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    client.app.state.config.setdefault("write_planned", {})["proposal_ttl_seconds"] = 120
    import time

    before = time.time()
    resp = _propose(client, _admin())
    after = time.time()

    expires_at = resp.json()["expires_at"]
    assert before + 119 <= expires_at <= after + 121


# --- audited, the same way every other mutation-adjacent route is -----------------------------


def test_a_successful_propose_is_audited_with_the_digest_and_intent(monkeypatch, tmp_path):
    captured: list[dict] = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    # The client first: `create_app` reconfigures logging and would drop a sink added
    # before it, leaving this test asserting against an empty list — passing vacuously.
    client = _client(monkeypatch, tmp_path)
    sink_id = logger.add(_sink, level="INFO")
    try:
        resp = _propose(client, _admin())
        digest = resp.json()["plan_digest"]
    finally:
        logger.remove(sink_id)

    assert captured, "no audit records captured — the assertions below would pass vacuously"
    proposals = [r for r in captured if r.get("action") == "device.write_planned.propose"]
    assert len(proposals) == 1
    assert proposals[0]["plan_digest"] == digest
    assert proposals[0]["intent"] == "register"
    assert proposals[0]["target"] == "sensor-1"
