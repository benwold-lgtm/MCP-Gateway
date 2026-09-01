# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0022, slice 4 — Review. Route-level tests; the store itself is covered by
`test_write_planned.py`, Propose by `test_write_planned_propose.py`.

Three properties carry this slice:

1. **Review needs `devices:write`, not a new scope** — `operator` already holds it, and
   `devices:write-planned` is never checked here, only minted.
2. **The grant belongs to the proposer, never the reviewer.** An admin approving an
   agent's proposal must produce a grant that agent — not the admin — can redeem.
3. **A proposal is one-shot and a repeatable grant's lifetime has a ceiling the reviewer
   cannot exceed**, only shorten.
"""

from __future__ import annotations

import itertools
import time

import pytest
from fastapi.testclient import TestClient
from loguru import logger

from device_mcp_gateway.rbac import Principal, scopes_for_role

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40
CALLER_KEY = "c" * 40


def _client(monkeypatch, tmp_path):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    client = TestClient(create_app(enable_write_planned=True))
    client.app.state.authenticator._keys[CALLER_KEY] = Principal(
        subject="key:agent1", scopes=scopes_for_role("caller"), auth_method="api_key"
    )
    return client


def _admin():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _caller():
    return {"Authorization": f"Bearer {CALLER_KEY}"}


PLAN = {"intent": "register", "hostname": "sensor-1", "base_url": "http://sensor-1.example/"}


def _propose(client, headers=None, **body):
    payload = {**PLAN, **body}
    return client.post("/v1/devices/plans", headers=headers or _caller(), json=payload)


# --- scope: devices:write, not a new one -----------------------------------------------------


def test_get_plan_requires_devices_write(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]

    resp = client.get(f"/v1/devices/plans/{proposal_id}", headers=_caller())

    assert resp.status_code == 403


def test_approve_requires_devices_write(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]

    resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_caller(), json={})

    assert resp.status_code == 403


def test_get_plan_succeeds_for_an_operator_scoped_reviewer(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]
    assert client.get(f"/v1/devices/plans/{proposal_id}", headers=_admin()).status_code == 200


# --- viewing a pending proposal -----------------------------------------------------------------


def test_get_returns_the_rendered_plan(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose(client).json()

    resp = client.get(f"/v1/devices/plans/{proposed['proposal_id']}", headers=_admin())

    assert resp.status_code == 200
    body = resp.json()
    assert body["plan"] == PLAN
    assert body["plan_digest"] == proposed["plan_digest"]


def test_get_404s_for_an_unknown_proposal(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    assert client.get("/v1/devices/plans/never-existed", headers=_admin()).status_code == 404


def test_get_404s_for_an_expired_proposal(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    client.app.state.config.setdefault("write_planned", {})["proposal_ttl_seconds"] = -1
    proposal_id = _propose(client).json()["proposal_id"]

    resp = client.get(f"/v1/devices/plans/{proposal_id}", headers=_admin())

    assert resp.status_code == 404


# --- approval mints the grant, and to the right subject ----------------------------------------


@pytest.mark.asyncio
async def test_approve_mints_a_grant_for_the_proposer_not_the_reviewer(monkeypatch, tmp_path):
    """The whole point of Review: an admin reviewer approves what `key:agent1` proposed, and
    only `key:agent1` — never the admin — can redeem the resulting grant."""
    client = _client(monkeypatch, tmp_path)
    proposed = _propose(client).json()

    resp = client.post(f"/v1/devices/plans/{proposed['proposal_id']}/approve", headers=_admin(), json={})
    assert resp.status_code == 200

    grants = client.app.state.write_planned_grants
    proposer_result = await grants.check_and_consume(digest=proposed["plan_digest"], subject="key:agent1")
    assert proposer_result.ok is True


@pytest.mark.asyncio
async def test_the_reviewer_cannot_redeem_a_grant_they_just_approved(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose(client).json()
    client.post(f"/v1/devices/plans/{proposed['proposal_id']}/approve", headers=_admin(), json={})

    grants = client.app.state.write_planned_grants
    reviewer_result = await grants.check_and_consume(
        digest=proposed["plan_digest"], subject="key:admin-or-whoever-reviewed"
    )
    assert reviewer_result.ok is False
    assert reviewer_result.reason == "subject_mismatch"


def test_approve_404s_for_an_unknown_proposal(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/devices/plans/never-existed/approve", headers=_admin(), json={})
    assert resp.status_code == 404


def test_a_proposal_cannot_be_approved_twice(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]

    first = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={})
    second = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={})

    assert first.status_code == 200
    assert second.status_code == 404


# --- single-use vs. repeatable, and the ttl ceiling --------------------------------------------


def test_approval_defaults_to_single_use(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]
    resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={})
    assert resp.json()["repeatable"] is False


def test_repeatable_is_an_explicit_choice_honored_when_made(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]
    resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={"repeatable": True})
    assert resp.json()["repeatable"] is True


def test_ttl_seconds_can_shorten_the_default_grant_window(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]
    before = time.time()

    resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={"ttl_seconds": 30})

    assert resp.status_code == 200
    assert before + 29 <= resp.json()["expires_at"] <= before + 31


def test_ttl_seconds_cannot_lengthen_a_single_use_grant_past_the_configured_ceiling(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    client.app.state.config.setdefault("write_planned", {})["grant_ttl_seconds"] = 100
    proposal_id = _propose(client).json()["proposal_id"]
    before = time.time()

    resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={"ttl_seconds": 10**9})

    assert resp.json()["expires_at"] <= before + 101


def test_ttl_seconds_cannot_lengthen_a_repeatable_grant_past_its_own_ceiling(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    client.app.state.config.setdefault("write_planned", {})["repeatable_grant_max_seconds"] = 200
    proposal_id = _propose(client).json()["proposal_id"]
    before = time.time()

    resp = client.post(
        f"/v1/devices/plans/{proposal_id}/approve",
        headers=_admin(),
        json={"repeatable": True, "ttl_seconds": 10**9},
    )

    assert resp.json()["expires_at"] <= before + 201


def test_ttl_seconds_must_be_a_positive_number(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    for bad in (0, -5, "soon", True):
        proposal_id = _propose(client).json()["proposal_id"]
        resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={"ttl_seconds": bad})
        assert resp.status_code == 400, bad


def test_an_empty_or_missing_body_defaults_cleanly(monkeypatch, tmp_path):
    """Approve is usually called with no body at all from a simple reviewer UI — a
    single-use grant at the deployment's default window."""
    client = _client(monkeypatch, tmp_path)
    proposal_id = _propose(client).json()["proposal_id"]
    resp = client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), content=b"")
    assert resp.status_code == 200
    assert resp.json()["repeatable"] is False


# --- audit ---------------------------------------------------------------------------------


def test_approval_is_audited_with_both_the_reviewer_and_the_proposer(monkeypatch, tmp_path):
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
        proposal_id = _propose(client).json()["proposal_id"]
        client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=_admin(), json={"repeatable": True})
    finally:
        logger.remove(sink_id)

    assert captured, "no audit records captured — the assertions below would pass vacuously"
    approvals = [r for r in captured if r.get("action") == "device.write_planned.approve"]
    assert len(approvals) == 1
    record = approvals[0]
    assert record["subject"] == "key:admin", "the record's own subject is the reviewer who made the call"
    assert record["proposer_subject"] == "key:agent1"
    assert record["repeatable"] is True
    assert record["target"] == "sensor-1"
