# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for the audit trail + URL redaction (F-55 / F-56 / F-59)."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from loguru import logger

from device_mcp_gateway.audit import audit_event, audit_request, redact_url, subject_of
from device_mcp_gateway.rbac import (
    ROLE_SCOPES,
    SCOPE_DEVICES_WRITE,
    Authenticator,
    Principal,
    authenticate_request,
    require_scope,
)


@pytest.fixture
def audit_log():
    """Capture emitted audit records (event='audit') as a list of `extra` dicts."""
    captured = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    sink_id = logger.add(_sink, level="INFO")
    yield captured
    logger.remove(sink_id)


# --- F-59 redaction ----------------------------------------------------------


def test_redact_url_strips_user_and_pass():
    assert redact_url("https://user:secret@dev.example.com/api") == "https://***@dev.example.com/api"


def test_redact_url_strips_user_only():
    assert redact_url("http://token@dev.local:8080/x?y=1") == "http://***@dev.local:8080/x?y=1"


def test_redact_url_leaves_clean_url_untouched():
    assert redact_url("https://dev.example.com:443/api?q=1") == "https://dev.example.com:443/api?q=1"


def test_redact_url_empty_and_none():
    assert redact_url("") == ""
    assert redact_url(None) == ""


# --- audit helpers -----------------------------------------------------------


def test_audit_event_emits_schema(audit_log):
    audit_event("device.create", subject="key:admin", outcome="success", rid="r1", target="dev1")
    assert len(audit_log) == 1
    e = audit_log[0]
    assert (e["action"], e["subject"], e["outcome"], e["rid"], e["target"]) == (
        "device.create",
        "key:admin",
        "success",
        "r1",
        "dev1",
    )


def test_subject_of_resolves_principal_or_unauthenticated():
    p = Principal(subject="key:ops", scopes=frozenset(), auth_method="api_key")
    req_with = SimpleNamespace(state=SimpleNamespace(principal=p))
    req_without = SimpleNamespace(state=SimpleNamespace())
    assert subject_of(req_with) == "key:ops"
    assert subject_of(req_without) == "unauthenticated"


def test_audit_request_pulls_subject_and_rid(audit_log):
    p = Principal(subject="key:admin", scopes=frozenset(), auth_method="api_key")
    req = SimpleNamespace(state=SimpleNamespace(principal=p, request_id="rid-9"))
    audit_request(req, "device.delete", outcome="success", target="dev2")
    assert audit_log[0]["subject"] == "key:admin"
    assert audit_log[0]["rid"] == "rid-9"
    assert audit_log[0]["action"] == "device.delete"


# --- F-55 auth-failure auditing (centralized at the rbac seam) ---------------


def _fake_request(authenticator=None, principal=None, request_id="rid-1", method="POST", path="/v1/devices"):
    state = SimpleNamespace(request_id=request_id)
    if principal is not None:
        state.principal = principal
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(authenticator=authenticator)),
        state=state,
        method=method,
        url=SimpleNamespace(path=path),
    )


@pytest.mark.asyncio
async def test_401_is_audited(audit_log):
    auth = Authenticator({"good": _p("admin")}, enabled=True)
    req = _fake_request(authenticator=auth)
    with pytest.raises(HTTPException) as exc:
        await authenticate_request(req, None)  # no credentials → 401
    assert exc.value.status_code == 401
    assert len(audit_log) == 1
    e = audit_log[0]
    assert e["action"] == "auth.authenticate"
    assert e["outcome"] == "denied"
    assert e["subject"] == "unauthenticated"
    assert e["target"] == "POST /v1/devices"
    assert e["rid"] == "rid-1"


@pytest.mark.asyncio
async def test_403_is_audited_with_actor_and_scope(audit_log):
    dep = require_scope(SCOPE_DEVICES_WRITE)
    req = _fake_request(principal=_p("viewer"), method="DELETE", path="/v1/devices/x")
    with pytest.raises(HTTPException) as exc:
        await dep(req)
    assert exc.value.status_code == 403
    e = audit_log[0]
    assert e["action"] == "authz.check"
    assert e["outcome"] == "denied"
    assert e["subject"] == "key:viewer"
    assert e["reason"] == f"missing_scope:{SCOPE_DEVICES_WRITE}"
    assert e["target"] == "DELETE /v1/devices/x"


@pytest.mark.asyncio
async def test_successful_authz_emits_no_audit(audit_log):
    dep = require_scope(SCOPE_DEVICES_WRITE)
    await dep(_fake_request(principal=_p("admin")))  # admin has the scope → allowed
    assert audit_log == []  # only denials are audited at this seam


def _p(role):
    return Principal(subject=f"key:{role}", scopes=ROLE_SCOPES[role], auth_method="api_key")
