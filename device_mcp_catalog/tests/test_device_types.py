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
