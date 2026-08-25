# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Slice 2: per-tenant assignment. Real Postgres only, same as test_device_types.py — no
fake/in-memory double for this store.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from device_mcp_catalog.app.main import create_app

pytestmark = pytest.mark.integration

API_TOKEN = "test-token"

DEVICE_TYPE = {
    "slug": "acme-sensor-x1",
    "name": "Acme Sensor X1",
    "upstream_kind": "openapi",
    "spec_path": "/openapi.json",
}

TENANT = "mcp-t-0123456789abcdef"


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(database_url):
    import asyncpg

    try:
        conn = await asyncpg.connect(database_url)
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")
    try:
        await conn.execute("TRUNCATE assignments, device_type_versions, device_types CASCADE")
    except asyncpg.UndefinedTableError:
        pass  # first run before any migration has created them yet
    finally:
        await conn.close()


def _client(monkeypatch, database_url) -> TestClient:
    monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    monkeypatch.setenv("CATALOG_API_TOKEN", API_TOKEN)
    return TestClient(create_app())


def _auth() -> dict:
    return {"Authorization": f"Bearer {API_TOKEN}"}


def _create_device_type(client) -> str:
    return client.post("/device-types", headers=_auth(), json=DEVICE_TYPE).json()["id"]


# --- assign ------------------------------------------------------------------------------


def test_assign_creates_an_active_assignment(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        resp = client.post(
            f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "key:admin"}
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["tenant_id"] == TENANT
    assert body["assigned_by"] == "key:admin"
    assert body["revoked_at"] is None


def test_assign_404s_for_an_unknown_device_type(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.post(
            "/device-types/00000000-0000-0000-0000-000000000000/assign",
            headers=_auth(),
            json={"tenant_id": TENANT, "assigned_by": "key:admin"},
        )
    assert resp.status_code == 404


def test_assigning_the_same_pair_twice_is_idempotent_not_a_conflict(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        first = client.post(
            f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "key:admin"}
        )
        second = client.post(
            f"/device-types/{type_id}/assign",
            headers=_auth(),
            json={"tenant_id": TENANT, "assigned_by": "key:someone-else"},
        )
    assert first.status_code == 201
    assert second.status_code == 201
    # The existing active row is returned, not a second one minted under the new caller.
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["assigned_by"] == "key:admin"


# --- revoke ------------------------------------------------------------------------------


def test_revoke_removes_it_from_the_tenants_active_list(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        client.post(f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "a"})

        revoke = client.delete(f"/device-types/{type_id}/assign/{TENANT}", headers=_auth())
        listing = client.get(f"/tenants/{TENANT}/assignments", headers=_auth())

    assert revoke.status_code == 204
    assert listing.json()["device_types"] == []


def test_revoke_404s_when_nothing_is_actively_assigned(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        resp = client.delete(f"/device-types/{type_id}/assign/{TENANT}", headers=_auth())
    assert resp.status_code == 404


def test_revoke_twice_404s_the_second_time(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        client.post(f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "a"})
        first = client.delete(f"/device-types/{type_id}/assign/{TENANT}", headers=_auth())
        second = client.delete(f"/device-types/{type_id}/assign/{TENANT}", headers=_auth())
    assert first.status_code == 204
    assert second.status_code == 404


def test_reassigning_after_a_revoke_creates_a_new_active_row(monkeypatch, database_url):
    """History is retained (ADR-0025), not overwritten — a revoke-then-reassign produces
    two rows, one revoked and one active, rather than un-revoking the old one."""
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        first = client.post(
            f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "a"}
        ).json()
        client.delete(f"/device-types/{type_id}/assign/{TENANT}", headers=_auth())
        second = client.post(
            f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "b"}
        ).json()

    assert second["id"] != first["id"]
    assert second["revoked_at"] is None


# --- listing for a tenant ------------------------------------------------------------------


def test_tenant_listing_reports_latest_version(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        client.post(f"/device-types/{type_id}/versions", headers=_auth(), json=DEVICE_TYPE)
        client.post(f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "a"})

        resp = client.get(f"/tenants/{TENANT}/assignments", headers=_auth())

    assert resp.status_code == 200
    types = resp.json()["device_types"]
    assert len(types) == 1
    assert types[0]["latest_version"] == 2


def test_tenant_listing_never_shows_another_tenants_assignment(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        client.post(f"/device-types/{type_id}/assign", headers=_auth(), json={"tenant_id": TENANT, "assigned_by": "a"})

        resp = client.get("/tenants/mcp-t-otherotherother1/assignments", headers=_auth())

    assert resp.json()["device_types"] == []


def test_tenant_listing_requires_a_token(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.get(f"/tenants/{TENANT}/assignments")
    assert resp.status_code == 401
