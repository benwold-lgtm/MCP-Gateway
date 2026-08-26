# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Slice 4: claim recording. Real Postgres only, same as test_assignments.py — no fake/
in-memory double for this store."""

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
        await conn.execute("TRUNCATE claims, assignments, device_type_versions, device_types CASCADE")
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


def test_record_claim_pins_the_curated_version(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        resp = client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["device_type_id"] == type_id
    assert body["version"] == 1
    assert body["tenant_id"] == TENANT
    assert body["hostname"] == "sensor-01"


def test_record_claim_404s_for_an_uncurated_version(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        resp = client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 7},
        )
    assert resp.status_code == 404


def test_record_claim_404s_for_an_unknown_device_type(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = client.post(
            "/device-types/00000000-0000-0000-0000-000000000000/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )
    assert resp.status_code == 404


def test_reclaiming_the_same_hostname_updates_the_pinned_version(monkeypatch, database_url):
    """A tenant deleting and re-registering the same hostname against a newer curated
    version replaces the pin rather than accumulating a second row for it."""
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        client.post(f"/device-types/{type_id}/versions", headers=_auth(), json=DEVICE_TYPE)
        first = client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        ).json()
        second = client.post(
            f"/device-types/{type_id}/claims",
            headers=_auth(),
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 2},
        ).json()

    assert second["id"] == first["id"]
    assert second["version"] == 2


def test_record_claim_requires_a_token(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        type_id = _create_device_type(client)
        resp = client.post(
            f"/device-types/{type_id}/claims",
            json={"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        )
    assert resp.status_code == 401
