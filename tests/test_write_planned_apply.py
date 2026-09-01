# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0022, slice 5 — Apply. The grant becomes exactly one write, and no more.

Propose is covered by `test_write_planned_propose.py`, Review by `test_write_planned_review.py`.
This slice's whole job is redemption: a live grant for the caller's own subject, scoped to the
exact digest resubmitted, gates `_apply_register`/`_apply_update` — the same functions
`register_device`/`update_device` call directly (extracted, not rewritten, in this slice so
Apply cannot drift from them). Properties covered:

1. **A valid grant is never a rubber stamp** — the SSRF guard and every other registration-time
   check still run at Apply, and can still fail it.
2. **No grant, the wrong grant, or someone else's grant refuses (403) before any write.**
3. **A resubmitted plan that no longer matches what was approved is a new plan**, refused the
   same way a missing grant is, with no write attempted.
4. **A single-use grant is consumed by redemption, not by a successful write** — a second
   Apply of the same digest fails even though the data is unchanged, and a failed Apply still
   spends it. A repeatable grant is the one exception: never consumed, so it tolerates both
   a byte-identical replay and a retry after a validation failure.
"""

from __future__ import annotations

import itertools

from fastapi.testclient import TestClient

from device_mcp_gateway.rbac import Principal, scopes_for_role

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40
CALLER_KEY = "c" * 40


def _client(monkeypatch, tmp_path, *, allow_private=True):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    if not allow_private:
        # conftest opts the whole suite into MCP_ALLOW_PRIVATE_TARGETS=true so ordinary
        # device tests don't need real DNS; clearing it here is what lets the SSRF guard
        # actually refuse something, the same pattern test_security_tier0.py uses.
        monkeypatch.delenv("MCP_ALLOW_PRIVATE_TARGETS", raising=False)
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


REGISTER_PLAN = {"intent": "register", "hostname": "sensor-1", "base_url": "http://sensor-1.example/"}


def _propose(client, plan, headers=None):
    return client.post("/v1/devices/plans", headers=headers or _caller(), json=plan)


def _approve(client, proposal_id, headers=None, **body):
    return client.post(f"/v1/devices/plans/{proposal_id}/approve", headers=headers or _admin(), json=body)


def _apply(client, plan, headers=None):
    return client.post("/v1/devices/plans/apply", headers=headers or _caller(), json=plan)


def _propose_and_approve(client, plan, **approve_body):
    proposed = _propose(client, plan).json()
    _approve(client, proposed["proposal_id"], **approve_body)
    return proposed


# --- the happy path -------------------------------------------------------------------------


def test_propose_approve_apply_registers_the_device(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)

    resp = _apply(client, proposed["plan"])

    assert resp.status_code == 200
    assert resp.json()["status"] == "registered"
    assert client.get("/v1/devices/sensor-1", headers=_admin()).status_code == 200


def test_apply_can_update_an_existing_device(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)
    _apply(client, proposed["plan"])

    update_plan = {"intent": "update", "hostname": "sensor-1", "rate_limit_rps": 5.0}
    proposed_update = _propose_and_approve(client, update_plan)

    resp = _apply(client, proposed_update["plan"])

    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"
    assert client.get("/v1/devices/sensor-1", headers=_admin()).json()["rate_limit_rps"] == 5.0


# --- a valid grant is never a rubber stamp: the SSRF guard still runs -----------------------


def test_apply_still_enforces_the_ssrf_guard_even_with_a_valid_grant(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, allow_private=False)
    plan = {"intent": "register", "hostname": "sneaky", "base_url": "http://127.0.0.1:1/"}
    proposed = _propose_and_approve(client, plan)

    resp = _apply(client, proposed["plan"])

    assert resp.status_code == 400
    assert client.get("/v1/devices/sneaky", headers=_admin()).status_code == 404


# --- missing / expired / wrong-subject grants refuse before any write -----------------------


def test_apply_refuses_with_no_grant_at_all(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose(client, REGISTER_PLAN).json()  # never approved

    resp = _apply(client, proposed["plan"])

    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "not_found"
    assert client.get("/v1/devices/sensor-1", headers=_admin()).status_code == 404


def test_apply_refuses_once_the_grant_has_expired(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    client.app.state.config.setdefault("write_planned", {})["grant_ttl_seconds"] = -1
    proposed = _propose_and_approve(client, REGISTER_PLAN)

    resp = _apply(client, proposed["plan"])

    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "expired"
    assert client.get("/v1/devices/sensor-1", headers=_admin()).status_code == 404


def test_apply_refuses_a_caller_other_than_the_proposer(monkeypatch, tmp_path):
    """`key:agent1` proposed; an admin applying it (rather than reviewing it) must not be
    able to redeem a grant that was never issued to them."""
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)

    wrong_caller = _apply(client, proposed["plan"], headers=_admin())
    assert wrong_caller.status_code == 403
    assert wrong_caller.json()["detail"]["reason"] == "subject_mismatch"
    assert client.get("/v1/devices/sensor-1", headers=_admin()).status_code == 404

    # The mismatch attempt must not have burned the real grant.
    right_caller = _apply(client, proposed["plan"])
    assert right_caller.status_code == 200


# --- an edited plan is a new plan, not a stale copy of the reviewed one ---------------------


def test_apply_refuses_a_plan_edited_since_review(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)
    edited = {**proposed["plan"], "base_url": "http://sensor-1-imposter.example/"}

    resp = _apply(client, edited)

    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "not_found"
    assert client.get("/v1/devices/sensor-1", headers=_admin()).status_code == 404

    # The grant for the plan that was actually reviewed is untouched.
    assert _apply(client, proposed["plan"]).status_code == 200


# --- single-use: consumed by redemption, exactly once ---------------------------------------


def test_a_single_use_grant_cannot_be_applied_twice(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)

    first = _apply(client, proposed["plan"])
    second = _apply(client, proposed["plan"])

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["detail"]["reason"] == "consumed"


def test_a_single_use_grant_is_spent_even_when_the_write_it_gates_fails(monkeypatch, tmp_path):
    """Redemption happens before validation, by design (it is what closes the check/write
    race) — so a plan that fails the SSRF guard still burns its single-use grant."""
    client = _client(monkeypatch, tmp_path, allow_private=False)
    plan = {"intent": "register", "hostname": "sneaky", "base_url": "http://127.0.0.1:1/"}
    proposed = _propose_and_approve(client, plan)

    first = _apply(client, proposed["plan"])
    second = _apply(client, proposed["plan"])

    assert first.status_code == 400
    assert second.status_code == 403
    assert second.json()["detail"]["reason"] == "consumed"


# --- repeatable: never consumed, survives byte-identical reapplication, refuses on any edit --


def test_a_repeatable_grant_survives_byte_identical_reapplication(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)
    _apply(client, proposed["plan"])

    update_plan = {"intent": "update", "hostname": "sensor-1", "rate_limit_rps": 5.0}
    proposed_update = _propose_and_approve(client, update_plan, repeatable=True)

    first = _apply(client, proposed_update["plan"])
    second = _apply(client, proposed_update["plan"])

    assert first.status_code == 200
    assert second.status_code == 200


def test_a_repeatable_grant_still_refuses_the_instant_the_plan_changes(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    proposed = _propose_and_approve(client, REGISTER_PLAN)
    _apply(client, proposed["plan"])

    update_plan = {"intent": "update", "hostname": "sensor-1", "rate_limit_rps": 5.0}
    proposed_update = _propose_and_approve(client, update_plan, repeatable=True)
    _apply(client, proposed_update["plan"])

    changed = {**proposed_update["plan"], "rate_limit_rps": 9.0}
    resp = _apply(client, changed)

    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "not_found"


def test_a_repeatable_grant_tolerates_a_retry_after_a_failed_write(monkeypatch, tmp_path):
    """Unlike single-use, a repeatable grant is never consumed, so a plan that fails
    validation can simply be fixed and reapplied under the same grant."""
    client = _client(monkeypatch, tmp_path, allow_private=False)
    plan = {"intent": "register", "hostname": "sneaky", "base_url": "http://127.0.0.1:1/"}
    proposed = _propose_and_approve(client, plan, repeatable=True)

    failed = _apply(client, proposed["plan"])
    assert failed.status_code == 400

    retried = _apply(client, proposed["plan"])
    assert retried.status_code == 400  # still a bad target, but refused by policy, not by the grant


# --- basic body validation, and audit --------------------------------------------------------


def test_apply_requires_a_known_intent(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _apply(client, {"intent": "delete", "hostname": "sensor-1"})
    assert resp.status_code == 400


def test_apply_requires_a_hostname(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _apply(client, {"intent": "register", "base_url": "http://x.example/"})
    assert resp.status_code == 400


def test_apply_is_audited_on_success_with_the_reviewer_and_repeatable_flag(monkeypatch, tmp_path):
    from loguru import logger

    captured: list[dict] = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    client = _client(monkeypatch, tmp_path)
    sink_id = logger.add(_sink, level="INFO")
    try:
        proposed = _propose_and_approve(client, REGISTER_PLAN, repeatable=True)
        _apply(client, proposed["plan"])
    finally:
        logger.remove(sink_id)

    applies = [r for r in captured if r.get("action") == "device.write_planned.apply"]
    assert len(applies) == 1
    record = applies[0]
    assert record["subject"] == "key:agent1"
    assert record["reviewer_subject"] == "key:admin"
    assert record["repeatable"] is True
    assert record["target"] == "sensor-1"
    assert record["plan_digest"] == proposed["plan_digest"]


def test_a_refused_apply_is_audited_as_denied(monkeypatch, tmp_path):
    from loguru import logger

    captured: list[dict] = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    client = _client(monkeypatch, tmp_path)
    sink_id = logger.add(_sink, level="INFO")
    try:
        proposed = _propose(client, REGISTER_PLAN).json()  # never approved
        _apply(client, proposed["plan"])
    finally:
        logger.remove(sink_id)

    applies = [r for r in captured if r.get("action") == "device.write_planned.apply"]
    assert len(applies) == 1
    assert applies[0]["outcome"] == "denied"
    assert applies[0]["reason"] == "not_found"
