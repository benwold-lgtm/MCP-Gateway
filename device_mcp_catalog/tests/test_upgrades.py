# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Slice 5: upgrade offers. Real Postgres only, same as test_claims.py — no fake/in-memory
double for this store, and this is also the first exercise of the `tool_set` JSONB column's
round-trip through asyncpg's codec.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from device_mcp_catalog.app.main import create_app

pytestmark = pytest.mark.integration

API_TOKEN = "test-token"
TENANT = "mcp-t-0123456789abcdef"

TOOL_A = [{"name": "read_sensor", "method": "GET", "schema": {"properties": {}, "required": []}}]
TOOL_B_COMPATIBLE = [
    {"name": "read_sensor", "method": "GET", "schema": {"properties": {}, "required": []}},
    {"name": "calibrate", "method": "POST", "schema": {"properties": {}, "required": []}},
]
TOOL_B_BREAKING = [
    {"name": "read_sensor", "method": "GET", "schema": {"properties": {"unit": {}}, "required": ["unit"]}}
]


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(database_url):
    import asyncpg

    try:
        conn = await asyncpg.connect(database_url)
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")
    try:
        await conn.execute("TRUNCATE claims, assignments, device_type_versions, device_types CASCADE")
    except asyncpg.UndefinedTableError:
        pass
    finally:
        await conn.close()


def _client(monkeypatch, database_url) -> TestClient:
    monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    monkeypatch.setenv("CATALOG_API_TOKEN", API_TOKEN)
    return TestClient(create_app())


def _auth() -> dict:
    return {"Authorization": f"Bearer {API_TOKEN}"}


def test_tool_set_round_trips_through_the_jsonb_codec(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.post(
            "/device-types",
            headers=_auth(),
            json={"slug": "acme-x1", "name": "Acme X1", "upstream_kind": "openapi", "tool_set": TOOL_A},
        )
        type_id = resp.json()["id"]
        detail = client.get(f"/device-types/{type_id}", headers=_auth()).json()
    assert detail["versions"][0]["tool_set"] == TOOL_A


def test_an_upgrade_offer_appears_with_a_compatible_diff(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = client.post(
            "/device-types",
            headers=_auth(),
            json={"slug": "acme-x1", "name": "Acme X1", "upstream_kind": "openapi", "tool_set": TOOL_A},
        ).json()["id"]
        client.post(
            f"/device-types/{type_id}/versions",
            headers=_auth(),
            json={"upstream_kind": "openapi", "tool_set": TOOL_B_COMPATIBLE},
        )
        client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )

        resp = client.get(f"/tenants/{TENANT}/upgrades", headers=_auth())

    assert resp.status_code == 200
    offers = resp.json()["offers"]
    assert len(offers) == 1
    offer = offers[0]
    assert offer["hostname"] == "sensor-01"
    assert offer["claimed_version"] == 1
    assert offer["current_version"] == 2
    assert offer["diff"]["added"] == ["calibrate"]
    assert offer["diff"]["breaking"] is False


def test_an_upgrade_offer_flags_a_breaking_diff(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = client.post(
            "/device-types",
            headers=_auth(),
            json={"slug": "acme-x1", "name": "Acme X1", "upstream_kind": "openapi", "tool_set": TOOL_A},
        ).json()["id"]
        client.post(
            f"/device-types/{type_id}/versions",
            headers=_auth(),
            json={"upstream_kind": "openapi", "tool_set": TOOL_B_BREAKING},
        )
        client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )

        resp = client.get(f"/tenants/{TENANT}/upgrades", headers=_auth())

    diff = resp.json()["offers"][0]["diff"]
    assert diff["breaking"] is True
    assert "unit" in diff["breaking_reasons"][0]


def test_no_offer_when_already_on_the_current_version(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = client.post(
            "/device-types",
            headers=_auth(),
            json={"slug": "acme-x1", "name": "Acme X1", "upstream_kind": "openapi", "tool_set": TOOL_A},
        ).json()["id"]
        client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )

        resp = client.get(f"/tenants/{TENANT}/upgrades", headers=_auth())

    assert resp.json()["offers"] == []


def test_diff_is_none_not_empty_when_a_version_declared_no_tool_set(monkeypatch, database_url):
    """A version curated without a tool_set means "no data to diff", never collapsed into
    "diffed and found no changes" (an empty-but-present ToolSetDiff)."""
    with _client(monkeypatch, database_url) as client:
        type_id = client.post(
            "/device-types",
            headers=_auth(),
            json={"slug": "acme-x1", "name": "Acme X1", "upstream_kind": "openapi"},  # no tool_set
        ).json()["id"]
        client.post(
            f"/device-types/{type_id}/versions",
            headers=_auth(),
            json={"upstream_kind": "openapi", "tool_set": TOOL_B_COMPATIBLE},
        )
        client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )

        resp = client.get(f"/tenants/{TENANT}/upgrades", headers=_auth())

    offer = resp.json()["offers"][0]
    assert offer["diff"] is None


def test_upgrades_requires_a_token(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.get(f"/tenants/{TENANT}/upgrades")
    assert resp.status_code == 401
