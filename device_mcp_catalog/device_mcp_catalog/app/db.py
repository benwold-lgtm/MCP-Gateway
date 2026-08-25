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
contract.

IDs are generated in Python (`uuid.uuid4()`), not by a Postgres default, so this module needs
no `pgcrypto`/`uuid-ossp` extension — one less thing a deployment has to enable.
"""

from __future__ import annotations

from typing import Optional

import asyncpg
from loguru import logger

#: Appended to (never rewritten) as later slices add tables — see the module docstring for
#: why this list is safe to replay against a database that already has some or all of it
#: applied.
_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS device_types (
        id          UUID PRIMARY KEY,
        slug        TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL,
        description TEXT,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS device_type_versions (
        id                  UUID PRIMARY KEY,
        device_type_id      UUID NOT NULL REFERENCES device_types(id),
        version             INTEGER NOT NULL,
        transport           TEXT NOT NULL DEFAULT 'sse',
        upstream_kind       TEXT NOT NULL DEFAULT 'openapi'
                                CHECK (upstream_kind IN ('openapi', 'mcp')),
        upstream_transport  TEXT NOT NULL DEFAULT 'http'
                                CHECK (upstream_transport IN ('http', 'sse')),
        -- Relative to the tenant-supplied base_url at claim time (openapi only — an mcp
        -- device has no spec_url at all, matching the gateway's own
        -- registry/validation.py `_validate_upstream` rule). Never an absolute URL: the
        -- device type is the appliance MODEL, and the host is the tenant's to supply.
        spec_path           TEXT,
        auth_kind           TEXT NOT NULL DEFAULT 'none'
                                CHECK (auth_kind IN ('none', 'api_key', 'oauth2')),
        fingerprint_policy  TEXT
                                CHECK (fingerprint_policy IN ('warn', 'enforce')),
        changelog           TEXT,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (device_type_id, version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS assignments (
        id              UUID PRIMARY KEY,
        device_type_id  UUID NOT NULL REFERENCES device_types(id),
        -- ADR-0019 opaque tenant identifier — never a customer name, so a compromised
        -- catalog leaks "which appliance models are assigned to which opaque tenant",
        -- not a customer roster.
        tenant_id       TEXT NOT NULL,
        assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        -- Attested by the caller (the console BFF passes through the acting provider
        -- subject), not derived here — this service has one shared token, not a
        -- per-caller identity, so it trusts the caller's own attestation of who acted.
        assigned_by     TEXT NOT NULL,
        -- NULL = currently assigned. Revoking sets this rather than deleting the row
        -- (ADR-0025 needs the history retained, not just the current state) — a fresh
        -- assign after a revoke inserts a NEW row rather than clearing this, so each
        -- assign/revoke cycle is its own auditable record.
        revoked_at      TIMESTAMPTZ
    )
    """,
    # At most one ACTIVE assignment per (type, tenant) — a partial index, not a plain
    # UNIQUE constraint, because a plain one would also block a legitimate re-assignment
    # after a revoke (two rows sharing the pair, one revoked, is exactly the allowed case).
    """
    CREATE UNIQUE INDEX IF NOT EXISTS assignments_active_unique
        ON assignments (device_type_id, tenant_id)
        WHERE revoked_at IS NULL
    """,
)


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
