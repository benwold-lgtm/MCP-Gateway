# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017: asking to act on a tenant and deciding who may are separate authorities.

This split exists because of a defect found by deploying the two planes as separate
processes for the first time. Every route on the support-request router sat behind one
`support:administer` dependency. A provider console must authenticate to a tenant's gateway
to *raise* a request — so the only credential that let it ask also let it approve, and a
provider could grant itself access to a tenant's fleet. That is precisely the authority
ADR-0017 says the tenant delegates and the provider never asserts.

It was invisible for as long as both planes ran as one process against one gateway: the
raiser and the approver were the same credential, so the collision had nothing to collide
with. The estate had exactly two reachable states, and neither was defensible — no
credential (the provider cannot ask at all, measured as a 401) or a credential that can
decide.

The property under test is therefore a *negative* one on each side, and the negatives are
what matter:

  * a provider (`support:request`) may ask and watch its own answer, and may do NOTHING else;
  * a tenant admin (`support:administer`) may decide, and may NOT raise a request on a
    provider's behalf;
  * and no identity approves its own request, even when configuration has handed it both.
"""

from __future__ import annotations

import itertools

from fastapi.testclient import TestClient

from device_mcp_gateway.rbac import (
    ALL_SCOPES,
    Principal,
    SCOPE_SUPPORT_ADMINISTER,
    SCOPE_SUPPORT_REQUEST,
    scopes_for_role,
)

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40
REQUESTER_KEY = "r" * 40
ADMINISTER_ONLY_KEY = "d" * 40
BOTH_KEY = "b" * 40

PROVIDER_SUBJECT = "idp:provops-cli"

RAISE_BODY = {
    "provider_subject": PROVIDER_SUBJECT,
    "requested_scopes": ["devices:read"],
    "justification": "customer ticket 1234",
}


def _client(monkeypatch, tmp_path):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    client = TestClient(create_app())
    keys = client.app.state.authenticator._keys
    # The provider's identity on this tenant's gateway. Its subject is deliberately the same
    # string the request is raised under, so the self-approval test below is not testing a
    # coincidence of unrelated names.
    keys[REQUESTER_KEY] = Principal(
        subject=PROVIDER_SUBJECT, scopes=frozenset({SCOPE_SUPPORT_REQUEST}), auth_method="api_key"
    )
    keys[ADMINISTER_ONLY_KEY] = Principal(
        subject="key:tenant-admin", scopes=frozenset({SCOPE_SUPPORT_ADMINISTER}), auth_method="api_key"
    )
    # An identity holding BOTH — the configuration this codebase can no longer produce by
    # accident, but which an estate running one directory across both planes can.
    keys[BOTH_KEY] = Principal(
        subject=PROVIDER_SUBJECT,
        scopes=frozenset({SCOPE_SUPPORT_REQUEST, SCOPE_SUPPORT_ADMINISTER}),
        auth_method="api_key",
    )
    return client


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _raise(client, key=REQUESTER_KEY, **overrides):
    return client.post("/v1/support-requests", headers=_h(key), json={**RAISE_BODY, **overrides})


# --- the vocabulary -------------------------------------------------------------------


def test_the_two_authorities_are_distinct_scopes():
    assert SCOPE_SUPPORT_REQUEST != SCOPE_SUPPORT_ADMINISTER
    assert {SCOPE_SUPPORT_REQUEST, SCOPE_SUPPORT_ADMINISTER} <= ALL_SCOPES


def test_the_provider_role_can_ask_and_nothing_else():
    """`support-requester` is the narrowest bundle in the system, and that is the point: a
    provider's standing permission on a tenant's gateway is permission to ASK."""
    assert scopes_for_role("support-requester") == frozenset({SCOPE_SUPPORT_REQUEST})


def test_no_tenant_role_grants_the_provider_scope_except_admin():
    """`operator` and `console` carry `support:administer` because a tenant admin approves
    through the console. Neither should be able to raise — that is the provider's side."""
    for role in ("operator", "console", "viewer", "caller", "auditor", "backup"):
        assert SCOPE_SUPPORT_REQUEST not in scopes_for_role(role), role


# --- the provider side: may ask, may do nothing else -----------------------------------


def test_a_provider_may_raise(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    assert _raise(client).status_code == 201


def test_a_provider_may_poll_its_own_request(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client).json()["request_id"]
    resp = client.get(
        f"/v1/support-requests/{rid}",
        headers=_h(REQUESTER_KEY),
        params={"provider_subject": PROVIDER_SUBJECT},
    )
    assert resp.status_code == 200, resp.text


def test_a_provider_may_not_approve(monkeypatch, tmp_path):
    """The defect this whole change exists for. Before the split this was a 200 and the
    provider walked away holding a grant over the tenant's fleet."""
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client).json()["request_id"]
    assert client.post(f"/v1/support-requests/{rid}/approve", headers=_h(REQUESTER_KEY)).status_code == 403


def test_a_provider_may_not_reject_list_or_revoke(monkeypatch, tmp_path):
    """Deciding is deciding. Rejecting someone else's request is a denial of service on the
    tenant's own support channel, and the live-grant list is the tenant's view of who is
    inside its fleet right now."""
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client).json()["request_id"]
    assert client.post(f"/v1/support-requests/{rid}/reject", headers=_h(REQUESTER_KEY)).status_code == 403
    assert client.get("/v1/support-requests", headers=_h(REQUESTER_KEY)).status_code == 403
    assert client.get("/v1/support-grants", headers=_h(REQUESTER_KEY)).status_code == 403
    assert client.delete("/v1/support-grants/anything", headers=_h(REQUESTER_KEY)).status_code == 403


def test_a_provider_may_not_touch_standing_consent(monkeypatch, tmp_path):
    """Standing consent is the tenant pre-approving a provider. A provider able to switch it
    on would be approving itself with extra steps — the exact shape, one level up."""
    client = _client(monkeypatch, tmp_path)
    h = _h(REQUESTER_KEY)
    assert client.get("/v1/support-requests/standing-consent", headers=h).status_code == 403
    assert client.post("/v1/support-requests/standing-consent", headers=h, json={}).status_code == 403
    assert client.delete("/v1/support-requests/standing-consent", headers=h).status_code == 403


# --- the tenant side: may decide, may not ask ------------------------------------------


def test_a_tenant_admin_may_not_raise(monkeypatch, tmp_path):
    """The mirror image, and not merely tidiness: a tenant identity able to raise could
    manufacture a request naming any provider_subject it liked and then approve it, which
    reconstructs the collision from the other end."""
    client = _client(monkeypatch, tmp_path)
    assert _raise(client, key=ADMINISTER_ONLY_KEY).status_code == 403


def test_a_tenant_admin_may_approve(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client).json()["request_id"]
    resp = client.post(f"/v1/support-requests/{rid}/approve", headers=_h(ADMINISTER_ONLY_KEY))
    assert resp.status_code == 200, resp.text
    assert "grant_id" in resp.json()


# --- the second line: nobody approves their own ----------------------------------------


def test_holding_both_scopes_still_cannot_self_approve(monkeypatch, tmp_path):
    """The belt-and-braces guard. The scope split is the real control — a provider cannot
    reach the approve route at all — so this covers the configuration that split cannot
    police: one identity legitimately given both, which an estate running a single directory
    across both planes will create without noticing."""
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client, key=BOTH_KEY).json()["request_id"]
    resp = client.post(f"/v1/support-requests/{rid}/approve", headers=_h(BOTH_KEY))
    assert resp.status_code == 403
    assert "raised it" in resp.json()["detail"]


def test_a_different_admin_may_still_approve_that_request(monkeypatch, tmp_path):
    """The guard must refuse the RAISER, not the request. If it rejected any approval of a
    request raised by a both-scoped identity, a real deployment would be stuck — and the
    guard would be denying the tenant the decision that is theirs to make."""
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client, key=BOTH_KEY).json()["request_id"]
    assert client.post(f"/v1/support-requests/{rid}/approve", headers=_h(ADMINISTER_ONLY_KEY)).status_code == 200


def test_the_self_approval_refusal_is_audited(monkeypatch, tmp_path):
    """A refusal here means a misconfigured estate, or an operator trying it on. Either way
    the tenant must be able to see it happened; a silent 403 is a security event nobody can
    count.

    Spies on `audit_request` rather than scraping stdout: loguru binds its sink at import,
    so a capsys assertion here passes or fails on log plumbing rather than on whether the
    route actually recorded anything.
    """
    client = _client(monkeypatch, tmp_path)
    rid = _raise(client, key=BOTH_KEY).json()["request_id"]

    calls = []
    import device_mcp_gateway.api.support_requests as mod

    real = mod.audit_request
    monkeypatch.setattr(mod, "audit_request", lambda *a, **k: (calls.append((a, k)), real(*a, **k))[1])

    assert client.post(f"/v1/support-requests/{rid}/approve", headers=_h(BOTH_KEY)).status_code == 403
    denied = [k for _, k in calls if k.get("reason") == "self_approval"]
    assert denied, f"no self_approval audit record; saw {[k.get('reason') for _, k in calls]}"
    assert denied[0]["outcome"] == "denied"
    assert denied[0]["target"] == PROVIDER_SUBJECT, "the record must name who tried"
