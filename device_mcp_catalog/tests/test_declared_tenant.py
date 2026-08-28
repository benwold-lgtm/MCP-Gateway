# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §7b: a credential can be correct and still be the wrong one.

§7a's rules trust the credential completely — deriving the tenant from it is the whole point —
so neither can notice a credential that was **delivered to the wrong console**. From this
service's side such a request is indistinguishable from a correct one: a credential arrived, it
identified a tenant, everything agreed. The mechanism working exactly as designed is the failure
mode.

The declaration is the second assertion that makes the disagreement visible. These tests are
where that is proven; like `test_caller_identity.py` they need no database, because the refusal
is decided before any query runs.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from device_mcp_catalog.app.auth import TENANT_HEADER
from device_mcp_catalog.app.main import create_app

PROVIDER_TOKEN = "provider-token"
TENANT_A_TOKEN = "tenant-a-token"
TENANT_B_TOKEN = "tenant-b-token"
TENANT_A = "t-aaaa"
TENANT_B = "t-bbbb"


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.setenv(
        "CATALOG_TENANT_TOKENS",
        f'{{"{TENANT_A}": "{TENANT_A_TOKEN}", "{TENANT_B}": "{TENANT_B_TOKEN}"}}',
    )
    monkeypatch.delenv("CATALOG_DATABASE_URL", raising=False)
    # The exposition server binds a real port and every test here builds an app. Off by
    # default in tests for the same reason the gateway's own suite does not start one: a port
    # collision must never decide whether a test passes.
    monkeypatch.setenv("CATALOG_METRICS_ENABLED", "false")
    return TestClient(create_app(), raise_server_exceptions=False)


def _headers(token: str, declare: str | None = None) -> dict:
    h = {"Authorization": f"Bearer {token}"}
    if declare is not None:
        h[TENANT_HEADER] = declare
    return h


def _counter(name: str, **labels) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


# --- the declaration is required -----------------------------------------------------------


def test_a_tenant_caller_declaring_its_own_tenant_proceeds(monkeypatch):
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(TENANT_A_TOKEN, TENANT_A))
    # Reaches the handler and fails at the absent database — which is how "the guard let this
    # through" is told apart from "the guard refused it" without needing a database.
    assert resp.status_code != 403


def test_a_tenant_caller_with_no_declaration_is_refused(monkeypatch):
    """An optional declaration is a check with an opt-out, taken by exactly the deployment that
    got it wrong. So it is required, and the refusal names its own reason rather than reusing
    the misdelivery one — a client that has not been updated is not a misdelivered credential."""
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(TENANT_A_TOKEN))
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "ERR_TENANT_NOT_DECLARED"


def test_an_empty_declaration_is_not_a_declaration(monkeypatch):
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(TENANT_A_TOKEN, "   "))
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "ERR_TENANT_NOT_DECLARED"


# --- misdelivery, both shapes --------------------------------------------------------------


def test_the_providers_credential_in_a_tenant_console_is_refused(monkeypatch):
    """§7b's headline case, and the one nothing else in this service can see: the provider's
    credential authenticates perfectly, as the provider, with every tenant's data in reach."""
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(PROVIDER_TOKEN, TENANT_A))
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "ERR_CREDENTIAL_MISDELIVERY"


def test_another_tenants_credential_is_refused(monkeypatch):
    """Tenant A's console, holding tenant B's credential. Every §7a rule is satisfied — the
    caller is a tenant, it has a valid credential, and it could name its own tenant
    consistently all day. Only the declaration disagrees."""
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_B}/assignments", headers=_headers(TENANT_B_TOKEN, TENANT_A))
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "ERR_CREDENTIAL_MISDELIVERY"


def test_misdelivery_is_decided_before_scope(monkeypatch):
    """The ordering §7b calls non-incidental, made observable.

    Tenant A's console holds tenant B's credential and asks about tenant B — which is exactly
    what a caller consistently wrong about its own identity would do, and it satisfies §7a's
    scope rule completely. If scope ran first this would be served. The error code is the only
    thing that can tell the two apart, so it is what is asserted.
    """
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_B}/assignments", headers=_headers(TENANT_B_TOKEN, TENANT_A))
    assert resp.json()["detail"]["error_code"] == "ERR_CREDENTIAL_MISDELIVERY"


def test_every_route_refuses_a_misdelivered_credential(monkeypatch):
    """Not one route — every route. Discovered from the OpenAPI schema rather than listed, so a
    route added later is covered without anyone remembering to add it here."""
    with _client(monkeypatch) as client:
        paths = [p for p in client.app.openapi()["paths"] if p not in ("/healthz", "/readyz", "/whoami")]
        assert paths
        for path in paths:
            for method in client.app.openapi()["paths"][path]:
                if method.upper() in ("HEAD", "OPTIONS"):
                    continue
                url = path.replace("{tenant_id}", TENANT_A).replace("{type_id}", "00000000-0000-0000-0000-0000000000ff")
                resp = client.request(method.upper(), url, headers=_headers(PROVIDER_TOKEN, TENANT_A), json={})
                assert resp.status_code == 403, f"{method.upper()} {path} served a misdelivered credential"
                assert resp.json()["detail"]["error_code"] == "ERR_CREDENTIAL_MISDELIVERY"


# --- what a declaration must NOT do --------------------------------------------------------


def test_the_provider_console_declares_nothing_and_is_served(monkeypatch):
    with _client(monkeypatch) as client:
        resp = client.get("/device-types", headers=_headers(PROVIDER_TOKEN))
    assert resp.status_code != 403


def test_a_declaration_is_not_authority(monkeypatch):
    """Declaring a tenant does not grant anything. A tenant caller declaring itself correctly is
    still a tenant caller: the credential decides what it may do, and the declaration only
    decides whether it is who it thinks it is."""
    with _client(monkeypatch) as client:
        resp = client.post("/device-types", headers=_headers(TENANT_A_TOKEN, TENANT_A), json={"slug": "x", "name": "X"})
    assert resp.status_code == 403
    # Refused as provider-only, NOT as a declaration problem — the two rules stay separable.
    assert resp.json()["detail"] == "this route is provider-only"


def test_declaring_the_provider_does_not_promote_a_tenant(monkeypatch):
    """A tenant console cannot declare its way into the provider class: the declaration is
    compared against the credential, never substituted for it."""
    with _client(monkeypatch) as client:
        resp = client.get("/device-types", headers=_headers(TENANT_A_TOKEN, "provider"))
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "ERR_CREDENTIAL_MISDELIVERY"


def test_whoami_needs_a_credential_but_no_declaration(monkeypatch):
    """§7b keeps /whoami as a diagnostic. Asking what you hold cannot require already knowing."""
    with _client(monkeypatch) as client:
        resp = client.get("/whoami", headers=_headers(TENANT_A_TOKEN))
        assert resp.status_code == 200
        assert resp.json() == {"kind": "tenant", "tenant_id": TENANT_A}
        assert client.get("/whoami").status_code == 401


# --- the condition reaches the alert plane -------------------------------------------------


def test_misdelivery_increments_the_alerting_counter(monkeypatch):
    """§7b's whole argument for giving this service a metrics plane. A refusal that only reaches
    a log is a refusal nobody is paged for, and a console holding another tenant's credential is
    a should-never-happen condition."""
    name = "catalog_credential_misdelivery_total"
    before = _counter(name, declared_tenant=TENANT_A, credential_kind="provider")
    with _client(monkeypatch) as client:
        client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(PROVIDER_TOKEN, TENANT_A))
    assert _counter(name, declared_tenant=TENANT_A, credential_kind="provider") == before + 1


def test_a_missing_declaration_does_not_page(monkeypatch):
    """Counted separately, deliberately. Conflating "a client is out of date" with "the wrong
    credential is deployed somewhere" would make the page-severity alert fire for the first."""
    misdelivery = "catalog_credential_misdelivery_total"
    missing = "catalog_tenant_declaration_missing_total"
    before_page = _counter(misdelivery, declared_tenant=TENANT_A, credential_kind="tenant")
    before_missing = _counter(missing, credential_tenant=TENANT_A)
    with _client(monkeypatch) as client:
        client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(TENANT_A_TOKEN))
    assert _counter(missing, credential_tenant=TENANT_A) == before_missing + 1
    assert _counter(misdelivery, declared_tenant=TENANT_A, credential_kind="tenant") == before_page


@pytest.mark.parametrize("token,declare", [(PROVIDER_TOKEN, None), (TENANT_A_TOKEN, TENANT_A)])
def test_a_correct_deployment_never_touches_either_counter(monkeypatch, token, declare):
    """The counters must be zero in normal operation, or the alert is noise on day one."""
    before = (
        _counter("catalog_credential_misdelivery_total", declared_tenant=TENANT_A, credential_kind="tenant"),
        _counter("catalog_tenant_declaration_missing_total", credential_tenant=TENANT_A),
    )
    with _client(monkeypatch) as client:
        client.get(f"/tenants/{TENANT_A}/assignments", headers=_headers(token, declare))
    assert (
        _counter("catalog_credential_misdelivery_total", declared_tenant=TENANT_A, credential_kind="tenant"),
        _counter("catalog_tenant_declaration_missing_total", credential_tenant=TENANT_A),
    ) == before
