# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Slice 0: liveness/readiness only. `/readyz` must report the database's absence or
unreachability as a named condition (a distinct status/reason), never a crash and never
indistinguishable from "the process didn't start" or "nothing curated yet" (ADR-0020 §7)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from device_mcp_catalog.app.main import create_app


def _client(monkeypatch, database_url: str = "") -> TestClient:
    if database_url:
        monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    else:
        monkeypatch.delenv("CATALOG_DATABASE_URL", raising=False)
    return TestClient(create_app())


def test_healthz_is_ok_even_with_no_database_configured(monkeypatch):
    """Liveness must not depend on the database at all — conflating the two would let a
    database blip take down a process that is otherwise perfectly able to serve traffic."""
    with _client(monkeypatch) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readyz_names_an_unconfigured_database_rather_than_crashing(monkeypatch):
    with _client(monkeypatch) as client:
        resp = client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["reason"] == "no database configured"


def test_readyz_names_an_unreachable_database_rather_than_crashing(monkeypatch):
    # A syntactically valid URL pointing at nothing listening — the pool constructs fine
    # (asyncpg pools lazily) and the failure surfaces on the first real query, which is
    # exactly the path `Database.ping()` is meant to catch and translate into `False`.
    with _client(monkeypatch, database_url="postgresql://postgres:test@localhost:1/nope") as client:
        resp = client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["reason"] == "database unreachable"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_readyz_is_ok_against_a_real_database(monkeypatch, database_url):
    import asyncpg

    try:
        conn = await asyncpg.connect(database_url)
        await conn.close()
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")

    with _client(monkeypatch, database_url=database_url) as client:
        resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
