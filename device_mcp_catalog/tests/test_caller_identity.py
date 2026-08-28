# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §7a: two caller classes, and the tenant is read from the credential.

**Deliberately not `pytest.mark.integration`.** Every other test in this service needs a real
Postgres and skips without one. The property §7a names as the whole check —

    A tenant caller naming a tenant other than its own is refused, on every route that names
    a tenant. Not filtered to an empty result, not silently rewritten to its own tenant —
    refused.

— is decided before any query runs, so it can be proven with no database at all, and it must
be: a cross-tenant authorization check that only runs where someone remembered to start
Postgres is a check that will one day quietly stop running. The handful of cases that genuinely
need stored rows are marked and isolated at the bottom.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from device_mcp_catalog.app.config import CatalogAuthConfigError, load_settings
from device_mcp_catalog.app.main import create_app

PROVIDER_TOKEN = "provider-token"
TENANT_A_TOKEN = "tenant-a-token"
TENANT_B_TOKEN = "tenant-b-token"
TENANT_A = "t-aaaa"
TENANT_B = "t-bbbb"

TYPE_ID = "00000000-0000-0000-0000-0000000000ff"


def _client(monkeypatch, *, database_url: str = "") -> TestClient:
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.setenv(
        "CATALOG_TENANT_TOKENS",
        f'{{"{TENANT_A}": "{TENANT_A_TOKEN}", "{TENANT_B}": "{TENANT_B_TOKEN}"}}',
    )
    if database_url:
        monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    else:
        monkeypatch.delenv("CATALOG_DATABASE_URL", raising=False)
    # `raise_server_exceptions=False` so that a request which PASSES authorization and then
    # fails at the (absent) database surfaces as a 500 response rather than an exception. That
    # distinction is load-bearing below: it is how "the guard let this through" is told apart
    # from "the guard refused it" without needing a database to tell them apart.
    return TestClient(create_app(), raise_server_exceptions=False)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- the caller table itself -------------------------------------------------------------


def test_provider_token_resolves_to_the_provider_caller(monkeypatch):
    with _client(monkeypatch) as client:
        # Provider-only and DB-backed: getting past the guard is the assertion, so anything
        # that is not a 401/403 proves the caller resolved as the provider.
        resp = client.get("/device-types", headers=_auth(PROVIDER_TOKEN))
    assert resp.status_code not in (401, 403)


def test_an_unknown_token_is_refused(monkeypatch):
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_auth("not-a-token"))
    assert resp.status_code == 401


def test_a_tenant_token_is_not_the_provider_token(monkeypatch):
    """The two classes are genuinely distinct credentials, not one token with a flag."""
    with _client(monkeypatch) as client:
        resp = client.post("/device-types", headers=_auth(TENANT_A_TOKEN), json={"slug": "x", "name": "X"})
    assert resp.status_code == 403


# --- the property: a tenant caller may name only itself ----------------------------------


def _routes_naming_a_tenant_in_the_path(app) -> list[tuple[str, str]]:
    """Every mounted route with a `{tenant_id}` path parameter, discovered rather than listed.

    §7a's property is "on **every** route that names a tenant", and a hand-maintained list
    would silently stop covering a route added later — which is exactly the shape of the defect
    this whole section exists to close.

    Read from the OpenAPI schema rather than by walking `app.routes`: this FastAPI wraps an
    included router in an `_IncludedRouter` whose own `path` is empty, so the obvious walk
    finds nothing and — worse — finds it *silently*, passing an empty list to a loop that then
    asserts nothing at all. The `assert routes` below exists because that is precisely how this
    test first failed.
    """
    found = []
    for path, operations in app.openapi()["paths"].items():
        if "{tenant_id}" not in path:
            continue
        for method in sorted(operations):
            if method.upper() not in ("HEAD", "OPTIONS"):
                found.append((method.upper(), path))
    return found


def test_every_path_route_naming_a_tenant_refuses_a_foreign_tenant(monkeypatch):
    with _client(monkeypatch) as client:
        routes = _routes_naming_a_tenant_in_the_path(client.app)
        assert routes, "expected at least one route with a {tenant_id} path parameter"
        for method, path in routes:
            url = path.replace("{tenant_id}", TENANT_B).replace("{type_id}", TYPE_ID)
            resp = client.request(method, url, headers=_auth(TENANT_A_TOKEN), json={})
            assert resp.status_code == 403, f"{method} {path} did not refuse a foreign tenant"


def test_a_foreign_tenant_is_refused_not_filtered_to_empty(monkeypatch):
    """The failure mode §7a warns about specifically: a scoped-to-nothing 200 looks like a
    tenant with no assignments, which is indistinguishable from a correct refusal in a log and
    invisible to the caller who just probed a neighbour."""
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_B}/assignments", headers=_auth(TENANT_A_TOKEN))
    assert resp.status_code == 403
    assert resp.json() != {"device_types": []}


def test_a_foreign_tenant_in_a_request_body_is_refused(monkeypatch):
    """`RecordClaim.tenant_id` is the body-named case — the one a path-only guard would miss,
    and the one §7a found could corrupt another tenant's claim provenance."""
    with _client(monkeypatch) as client:
        resp = client.post(
            f"/device-types/{TYPE_ID}/claims",
            headers=_auth(TENANT_A_TOKEN),
            json={"tenant_id": TENANT_B, "hostname": "probe.example", "version": 1},
        )
    assert resp.status_code == 403


def test_naming_its_own_tenant_is_not_refused(monkeypatch):
    """The other half of the property: the guard scopes, it does not simply deny.

    With no database configured this request fails *after* authorization, which is the point —
    a 500 from an absent database proves it reached the handler, where a 403 would prove it did
    not. Both halves matter: a guard that refused everything would pass the test above.
    """
    with _client(monkeypatch) as client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_auth(TENANT_A_TOKEN))
    assert resp.status_code != 403


def test_a_tenant_caller_cannot_read_the_unscoped_catalog(monkeypatch):
    """§7a's second rule. Scoping only the assignments route would still let a tenant read the
    provider's whole catalogue, which is estate shape they have no claim to."""
    with _client(monkeypatch) as client:
        resp = client.get("/device-types", headers=_auth(TENANT_A_TOKEN))
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/device-types", {"slug": "x", "name": "X"}),
        ("POST", f"/device-types/{TYPE_ID}/versions", {}),
        ("GET", "/device-types", None),
        ("POST", f"/device-types/{TYPE_ID}/assign", {"tenant_id": TENANT_A, "assigned_by": "someone"}),
        ("DELETE", f"/device-types/{TYPE_ID}/assign/{TENANT_A}", None),
    ],
)
def test_curation_and_assignment_are_provider_only(monkeypatch, method, path, body):
    """A tenant curating a type, or assigning one to itself, is the third bullet in §7a's
    finding. Note the assign case names the tenant's *own* id: it is refused for being a
    provider act, not for naming a neighbour, so the two rules are not covering for each
    other."""
    with _client(monkeypatch) as client:
        resp = client.request(method, path, headers=_auth(TENANT_A_TOKEN), json=body)
    assert resp.status_code == 403


# --- a malformed caller table is fatal, never degraded ------------------------------------


def test_a_tenant_token_equal_to_the_providers_refuses_to_start(monkeypatch):
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.setenv("CATALOG_TENANT_TOKENS", f'{{"{TENANT_A}": "{PROVIDER_TOKEN}"}}')
    with pytest.raises(CatalogAuthConfigError, match="provider's own token"):
        load_settings()


def test_two_tenants_sharing_a_token_refuses_to_start(monkeypatch):
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.setenv("CATALOG_TENANT_TOKENS", f'{{"{TENANT_A}": "shared", "{TENANT_B}": "shared"}}')
    with pytest.raises(CatalogAuthConfigError, match="same token"):
        load_settings()


def test_an_empty_tenant_token_refuses_to_start(monkeypatch):
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.setenv("CATALOG_TENANT_TOKENS", f'{{"{TENANT_A}": ""}}')
    with pytest.raises(CatalogAuthConfigError, match="empty token"):
        load_settings()


def test_unparseable_tenant_tokens_refuse_to_start(monkeypatch):
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.setenv("CATALOG_TENANT_TOKENS", "not json")
    with pytest.raises(CatalogAuthConfigError, match="not valid JSON"):
        load_settings()


def test_no_tenant_tokens_is_a_valid_provider_only_deployment(monkeypatch):
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.delenv("CATALOG_TENANT_TOKENS", raising=False)
    assert load_settings().tenant_tokens == {}


# --- the cases that genuinely need stored rows --------------------------------------------

integration = pytest.mark.integration


@integration
def test_a_tenant_reads_its_own_assignments_and_the_type_behind_them(monkeypatch, database_url):
    """End to end on a real store: assign to tenant A as the provider, then read it back as
    tenant A, and confirm tenant B can see neither the assignment nor the type detail."""
    import asyncpg  # noqa: F401 — imported for the skip check below only

    with _client(monkeypatch, database_url=database_url) as client:
        if client.get("/readyz").status_code != 200:
            pytest.skip("real Postgres not reachable")

        created = client.post(
            "/device-types",
            headers=_auth(PROVIDER_TOKEN),
            json={"slug": "scoped-probe", "name": "Scoped Probe", "upstream_kind": "mcp"},
        )
        assert created.status_code in (201, 409)
        if created.status_code == 409:
            listed = client.get("/device-types", headers=_auth(PROVIDER_TOKEN)).json()["device_types"]
            type_id = next(t["id"] for t in listed if t["slug"] == "scoped-probe")
        else:
            type_id = created.json()["id"]

        assigned = client.post(
            f"/device-types/{type_id}/assign",
            headers=_auth(PROVIDER_TOKEN),
            json={"tenant_id": TENANT_A, "assigned_by": "provider-op"},
        )
        assert assigned.status_code == 201

        mine = client.get(f"/tenants/{TENANT_A}/assignments", headers=_auth(TENANT_A_TOKEN))
        assert mine.status_code == 200
        assert any(t["id"] == type_id for t in mine.json()["device_types"])

        assert client.get(f"/device-types/{type_id}", headers=_auth(TENANT_A_TOKEN)).status_code == 200

        # Tenant B was never assigned this type. It reads as absent, NOT as forbidden: a
        # distinguishable "exists but not yours" would let a tenant enumerate the estate's
        # catalogue one id at a time, which is the same thing the unscoped list route withholds.
        assert client.get(f"/device-types/{type_id}", headers=_auth(TENANT_B_TOKEN)).status_code == 404

        client.delete(f"/device-types/{type_id}/assign/{TENANT_A}", headers=_auth(PROVIDER_TOKEN))
        # A revoked assignment is absent, so the type detail closes behind it too.
        assert client.get(f"/device-types/{type_id}", headers=_auth(TENANT_A_TOKEN)).status_code == 404
