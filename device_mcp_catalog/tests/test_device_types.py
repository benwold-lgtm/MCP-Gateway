# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Slice 1: device-type curation. No fake/in-memory double for this store — every test here
runs against a real Postgres and is skipped (not failed) when one isn't reachable, matching
this project's established standard.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from device_mcp_catalog.app.main import create_app

pytestmark = pytest.mark.integration

API_TOKEN = "test-token"

REGISTER_PLAN = {
    "slug": "acme-sensor-x1",
    "name": "Acme Sensor X1",
    "description": "A temperature/humidity sensor line",
    "upstream_kind": "openapi",
    "spec_path": "/openapi.json",
}


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(database_url):
    import asyncpg

    try:
        conn = await asyncpg.connect(database_url)
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")
    try:
        await conn.execute("TRUNCATE device_type_versions, device_types CASCADE")
    except asyncpg.UndefinedTableError:
        pass  # first run before any migration has created them yet
    finally:
        await conn.close()


def _client(monkeypatch, database_url, *, token: str = API_TOKEN) -> TestClient:
    monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    if token:
        monkeypatch.setenv("CATALOG_API_TOKEN", token)
    else:
        monkeypatch.delenv("CATALOG_API_TOKEN", raising=False)
    return TestClient(create_app())


def _auth(token: str = API_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- auth ------------------------------------------------------------------------------


def test_curation_refuses_with_no_token_configured(monkeypatch, database_url):
    with _client(monkeypatch, database_url, token="") as client:
        resp = client.get("/device-types", headers=_auth())
    assert resp.status_code == 401


def test_curation_refuses_a_wrong_token(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.get("/device-types", headers=_auth("wrong"))
    assert resp.status_code == 401


def test_curation_refuses_no_token_at_all(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.get("/device-types")
    assert resp.status_code == 401


def test_curation_succeeds_with_the_right_token(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.get("/device-types", headers=_auth())
    assert resp.status_code == 200


# --- create ------------------------------------------------------------------------------


def test_create_device_type_mints_version_one(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN)
    assert resp.status_code == 201
    body = resp.json()
    assert body["slug"] == "acme-sensor-x1"
    assert body["latest_version"] == 1
    assert len(body["versions"]) == 1
    assert body["versions"][0]["version"] == 1
    assert body["versions"][0]["spec_path"] == "/openapi.json"


def test_create_device_type_refuses_a_duplicate_slug(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        first = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN)
        second = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN)
    assert first.status_code == 201
    assert second.status_code == 409


def test_create_device_type_refuses_a_spec_path_on_an_mcp_device(monkeypatch, database_url):
    plan = {**REGISTER_PLAN, "upstream_kind": "mcp", "spec_path": "/openapi.json"}
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=plan)
    assert resp.status_code == 400


def test_create_device_type_allows_no_spec_path_on_an_mcp_device(monkeypatch, database_url):
    plan = {**REGISTER_PLAN, "upstream_kind": "mcp", "spec_path": None}
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=plan)
    assert resp.status_code == 201


# --- versions ------------------------------------------------------------------------------


def test_add_version_increments_monotonically(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        created = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN).json()
        v2 = client.post(
            f"/device-types/{created['id']}/versions",
            headers=_auth(),
            json={**REGISTER_PLAN, "changelog": "widened a timeout"},
        )
        v3 = client.post(
            f"/device-types/{created['id']}/versions",
            headers=_auth(),
            json={**REGISTER_PLAN, "changelog": "added a sensor field"},
        )
    assert v2.status_code == 201
    assert v2.json()["version"] == 2
    assert v3.status_code == 201
    assert v3.json()["version"] == 3


def test_add_version_404s_for_an_unknown_device_type(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.post(
            "/device-types/00000000-0000-0000-0000-000000000000/versions", headers=_auth(), json=REGISTER_PLAN
        )
    assert resp.status_code == 404


def test_get_device_type_returns_full_version_history(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        created = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN).json()
        client.post(f"/device-types/{created['id']}/versions", headers=_auth(), json=REGISTER_PLAN)

        resp = client.get(f"/device-types/{created['id']}", headers=_auth())

    assert resp.status_code == 200
    body = resp.json()
    assert body["latest_version"] == 2
    assert [v["version"] for v in body["versions"]] == [1, 2]


def test_get_device_type_404s_for_an_unknown_id(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.get("/device-types/00000000-0000-0000-0000-000000000000", headers=_auth())
    assert resp.status_code == 404


# --- list ------------------------------------------------------------------------------


def test_list_device_types_reports_latest_version_per_type(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        created = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN).json()
        client.post(f"/device-types/{created['id']}/versions", headers=_auth(), json=REGISTER_PLAN)
        other = {**REGISTER_PLAN, "slug": "other-device"}
        client.post("/device-types", headers=_auth(), json=other)

        resp = client.get("/device-types", headers=_auth())

    assert resp.status_code == 200
    by_slug = {d["slug"]: d["latest_version"] for d in resp.json()["device_types"]}
    assert by_slug == {"acme-sensor-x1": 2, "other-device": 1}


# --- product facts the tenant was being asked to guess (ADR-0020 §2) ------------------------
#
# Where the API key goes and what the appliance tolerates are properties of the PRODUCT. The
# tenant was typing them into the claim form from a vendor PDF, and getting `api_key_name`
# wrong yields a 401 at first contact that reads like a bad key rather than a misplaced one.
#
# The credential VALUE stays the tenant's half throughout — only its position is curated.


def test_a_version_carries_where_the_api_key_goes_and_what_the_appliance_tolerates(monkeypatch, database_url):
    plan = {
        **REGISTER_PLAN,
        "auth_kind": "api_key",
        "api_key_location": "header",
        "api_key_name": "X-API-Key",
        "recommended_rate_limit_rps": 10.5,
    }
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=plan)
        assert resp.status_code == 201, resp.text
        # Read back through the route a claim actually uses, not the create response — the
        # column has to survive the round trip, which is what a migration can get wrong.
        detail = client.get(f"/device-types/{resp.json()['id']}", headers=_auth()).json()

    version = detail["versions"][0]
    assert version["api_key_location"] == "header"
    assert version["api_key_name"] == "X-API-Key"
    assert version["recommended_rate_limit_rps"] == 10.5


def test_api_key_fields_are_refused_when_the_type_uses_a_different_auth_kind(monkeypatch, database_url):
    """Refused rather than ignored, for the reason §4a gave for mutual exclusivity: a curated
    field that silently does nothing is one a curator believes is in effect."""
    plan = {**REGISTER_PLAN, "auth_kind": "oauth2", "api_key_name": "X-API-Key"}
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=plan)
    assert resp.status_code == 422


def test_a_nonsense_api_key_location_is_refused(monkeypatch, database_url):
    plan = {**REGISTER_PLAN, "auth_kind": "api_key", "api_key_location": "body"}
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=plan)
    assert resp.status_code == 422


def test_a_recommended_rate_limit_must_be_positive(monkeypatch, database_url):
    """Zero is not "no limit" — it is a device that may make no requests at all. Absent is how
    "no recommendation" is said, and the two must not collapse."""
    with _client(monkeypatch, database_url) as client:
        zero = client.post("/device-types", headers=_auth(), json={**REGISTER_PLAN, "recommended_rate_limit_rps": 0})
        negative = client.post(
            "/device-types", headers=_auth(), json={**REGISTER_PLAN, "recommended_rate_limit_rps": -1}
        )
    assert zero.status_code == 422
    assert negative.status_code == 422


def test_a_version_curated_before_these_fields_existed_reads_as_no_answer(monkeypatch, database_url):
    """`None` means "the curator has not said", which the claim flow must distinguish from a
    curated value — it falls back to asking the tenant rather than defaulting to something
    plausible. A version created without them must therefore read as null, not as a default."""
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN)
        version = resp.json()["versions"][0]

    assert version["api_key_location"] is None
    assert version["api_key_name"] is None
    assert version["recommended_rate_limit_rps"] is None


# --- the value space the gateway will actually accept -------------------------------------


def test_a_transport_the_gateway_cannot_serve_is_refused_at_curation(monkeypatch, database_url):
    """`transport` was the one curated field with no constraint on either side of it.

    The gateway's `_validate_transport` accepts exactly `"sse"`. An unconstrained value here
    was accepted at curation, appeared in every assigned tenant's console, and then failed
    each claim individually with a message naming a field the tenant never supplied and
    cannot change — the curator, the only party who can fix it, was never told.

    Same shape as LR-48 (`upstream_transport` sent unconditionally to an OpenAPI device), one
    column over: `upstream_transport` has had both a Literal and a DB CHECK since the first
    release, and sits directly below the column that had neither.
    """
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json={**REGISTER_PLAN, "transport": "http"})
    assert resp.status_code == 422
    assert "transport" in resp.text


def test_a_version_still_defaults_to_the_transport_the_gateway_serves(monkeypatch, database_url):
    """The constraint must not have narrowed the default out from under existing curation."""
    with _client(monkeypatch, database_url) as client:
        resp = client.post("/device-types", headers=_auth(), json=REGISTER_PLAN)
    assert resp.status_code == 201, resp.text
    assert resp.json()["versions"][0]["transport"] == "sse"
