# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
import os

import pytest
import pytest_asyncio

# Mirrors device-mcp-gateway's tests/conftest.py `real_redis` pattern: a dedicated test
# database, skip (not fail) when unreachable so the suite still runs where Postgres isn't
# available, matching this project's "tested against the real tier, not solely a fake"
# standard (there is no fake/in-memory double for this store at all — it's real or skipped).
TEST_DATABASE_URL = os.getenv("CATALOG_TEST_DATABASE_URL", "postgresql://postgres:test@localhost:55432/catalog_test")


@pytest.fixture
def database_url() -> str:
    return TEST_DATABASE_URL


@pytest_asyncio.fixture
async def real_db():
    import asyncpg

    from device_mcp_catalog.app.db import Database

    try:
        conn = await asyncpg.connect(TEST_DATABASE_URL)
        await conn.close()
    except Exception:
        pytest.skip(f"real Postgres not reachable at {TEST_DATABASE_URL}")

    db = Database(TEST_DATABASE_URL)
    await db.connect()
    try:
        yield db
    finally:
        await db.close()
