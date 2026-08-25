# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Postgres connection pool + idempotent schema migrations.

Raw SQL via `asyncpg`, no ORM — the same choice `device_mcp_gateway/storage/sqlite_store.py`
already made for the gateway's own embedded store, kept here for consistency rather than
introducing a second persistence style (SQLAlchemy) for this project's first Postgres user.

Migrations are a plain ordered list of idempotent DDL statements applied at startup, the same
shape `sqlite_store.py`'s `_MIGRATIONS` uses — `CREATE TABLE IF NOT EXISTS` plus
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` for every addition after the first release. Postgres
supports `IF NOT EXISTS` on `ADD COLUMN` directly (SQLite does not, which is why the gateway's
own version wraps each statement in a swallowed exception instead) — so this runner does not
need that try/except dance, but keeps the same "additive, never destructive, safe to re-run"
contract. Slice 1 appends `device_types`/`device_type_versions` here; slice 2 appends
`assignments`. No table exists yet in slice 0 — this module is connection + health only.
"""

from __future__ import annotations

from typing import Optional

import asyncpg
from loguru import logger

#: Slice 0 has no schema of its own yet. Appended to (never rewritten) as later slices add
#: tables — see the module docstring for why this list is safe to replay against a database
#: that already has some or all of it applied.
_MIGRATIONS: tuple[str, ...] = ()


class Database:
    """Owns the one connection pool this service uses. Deliberately thin: `asyncpg` already
    pools and pipelines, so there is nothing here beyond a documented startup/shutdown/health
    lifecycle for `main.py`'s lifespan to drive."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=10)
        async with self._pool.acquire() as conn:
            for stmt in _MIGRATIONS:
                await conn.execute(stmt)
        logger.info("catalog database pool connected and migrations applied")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def ping(self) -> bool:
        """`True` iff a trivial round trip succeeds. Never raises — a caller checking
        readiness must get a boolean, not an exception to also handle."""
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # noqa: BLE001 — this is the health check; any failure means "not ready"
            logger.warning(f"catalog database ping failed: {exc}")
            return False

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("Database.connect() has not been called")
        return self._pool
