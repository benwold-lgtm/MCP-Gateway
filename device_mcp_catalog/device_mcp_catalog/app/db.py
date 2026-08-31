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

import json
from typing import Optional

import asyncpg
from loguru import logger


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Registers a codec so `jsonb` round-trips as Python lists/dicts through asyncpg,
    which otherwise hands back (and expects) raw JSON text for that type. Needed the
    moment `tool_set` (slice 5) became this service's first JSONB column."""
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


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
    # ADR-0020 §4: which device-type VERSION a tenant's device was registered from — the
    # baseline slice 5's upgrade-offer diff needs, and the thing that makes "pinned"
    # checkable independently of whatever the tenant's own gateway record later becomes.
    # The (device_type_id, version) FK targets device_type_versions' own UNIQUE pair, so a
    # claim can never point at a version that was never curated. One row per (tenant,
    # hostname): a hostname is claimed at most once at a time in a tenant's own registry,
    # so a second claim under the same hostname (a delete + re-register) replaces the row
    # rather than accumulating stale ones — see ClaimRepo.record_claim's ON CONFLICT.
    """
    CREATE TABLE IF NOT EXISTS claims (
        id              UUID PRIMARY KEY,
        device_type_id  UUID NOT NULL,
        version         INTEGER NOT NULL,
        tenant_id       TEXT NOT NULL,
        hostname        TEXT NOT NULL,
        claimed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        FOREIGN KEY (device_type_id, version) REFERENCES device_type_versions (device_type_id, version)
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS claims_tenant_hostname_unique
        ON claims (tenant_id, hostname)
    """,
    # ADR-0020 §4, slice 5: the tool set a version's shape is DECLARED to imply — hand-
    # entered by the curator at add_version time (the gateway's own `declared_*` fields on
    # DeviceConfig are the precedent for this word: self-reported, never independently
    # measured here, since the catalog never fetches a live spec). Nullable: a version
    # curated before this column existed, or one the curator never filled in, has nothing
    # to diff — a distinct condition from "diffed and found no changes" (repo.py's
    # UpgradeOffer keeps that distinction, never collapsing "no data" into "no changes").
    """
    ALTER TABLE device_type_versions ADD COLUMN IF NOT EXISTS tool_set JSONB
    """,
    # ADR-0020 §2: three more facts about the PRODUCT, which the provider knows and the
    # tenant was being asked to guess.
    #
    # `api_key_location` / `api_key_name` are where the credential goes — `X-API-Key` in a
    # header, say. That is a property of the appliance's API, not of anyone's deployment of
    # it, and a tenant who guesses wrong gets a 401 at first contact that reads like a bad
    # key. The credential VALUE stays firmly the tenant's half; only its position is curated.
    #
    # `recommended_rate_limit_rps` is a recommendation and named as one. The provider knows
    # what the appliance tolerates; the tenant may legitimately want to be more conservative,
    # and a provider-imposed ceiling on a tenant's own gateway would cross the plane boundary
    # §2 keeps. So it pre-fills the claim form and constrains nothing.
    #
    # All three nullable: versions curated before these columns existed have no answer, which
    # is a different condition from "the curator said none" and is why the claim flow falls
    # back to asking rather than defaulting.
    """
    ALTER TABLE device_type_versions ADD COLUMN IF NOT EXISTS api_key_location TEXT
    """,
    """
    ALTER TABLE device_type_versions ADD COLUMN IF NOT EXISTS api_key_name TEXT
    """,
    """
    ALTER TABLE device_type_versions
        ADD COLUMN IF NOT EXISTS recommended_rate_limit_rps DOUBLE PRECISION
    """,
    # Added as a separate statement rather than inline above: ADD COLUMN IF NOT EXISTS is
    # idempotent, ADD CONSTRAINT is not, so the check is applied only when absent. Without
    # the guard a second startup fails on an already-migrated database, which presents as a
    # service that will not start rather than as a migration that ran twice.
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'device_type_versions_api_key_location'
        ) THEN
            ALTER TABLE device_type_versions
                ADD CONSTRAINT device_type_versions_api_key_location
                CHECK (api_key_location IS NULL OR api_key_location IN ('header', 'query', 'cookie'));
        END IF;
    END $$
    """,
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'device_type_versions_rate_limit_positive'
        ) THEN
            ALTER TABLE device_type_versions
                ADD CONSTRAINT device_type_versions_rate_limit_positive
                CHECK (recommended_rate_limit_rps IS NULL OR recommended_rate_limit_rps > 0);
        END IF;
    END $$
    """,
    # ADR-0024 §10 / ADR-0020 §7a: the tenant caller table, moved from config into storage.
    #
    # §7a shipped that table as `CATALOG_TENANT_TOKENS`, a static env map, because nothing
    # could mint one at the time. §10 is what mints them: approving an enrolment is "the
    # moment a tenant first needs catalog access, and the moment both sides' identities are
    # known". A credential provisioned by hand is step 9 of that record's nine steps, so it
    # has to be issuable by an API call.
    #
    # Config entries are NOT replaced by this table — they keep working, and remain the way
    # to bootstrap a tenant that predates enrolment. `auth.py` reads both.
    #
    # The token is stored as a SHA-256 HASH, never verbatim. This service only ever needs to
    # RECOGNISE a presented credential, never to present one, so a one-way form costs it
    # nothing — and a dump of this table is then not a set of live credentials. The env map
    # cannot have that property, which is one more reason for issued credentials to become
    # the normal path.
    """
    CREATE TABLE IF NOT EXISTS tenant_credentials (
        id              UUID PRIMARY KEY,
        tenant_id       TEXT NOT NULL,
        credential_hash TEXT NOT NULL UNIQUE,
        label           TEXT NOT NULL DEFAULT '',
        issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        issued_by       TEXT NOT NULL DEFAULT '',
        revoked_at      TIMESTAMPTZ
    )
    """,
    # The lookup `auth.py` performs for every request from an issued tenant credential: hash
    # the bearer, find the live row. Partial on `revoked_at IS NULL` so a revoked credential
    # leaves the index entirely rather than being filtered out after the fact — revocation is
    # the only control an issued credential has, so the fast path must be the live one.
    """
    CREATE INDEX IF NOT EXISTS tenant_credentials_live
        ON tenant_credentials (credential_hash)
        WHERE revoked_at IS NULL
    """,
    # ADR-0024 §11: the provider's tenant registry — WHO A PROVIDER SERVES, deliberately apart
    # from the device-type tables above, which describe what a provider curates.
    #
    # Moved out of `PROVIDER_TENANT_REGISTRY` (a JSON array in the console's environment)
    # because config is the right tool for what is set at deploy time and changes rarely, and
    # enrolment/revocation are the opposite shape: routine, in-band, and required to take effect
    # without redeploying the console. §10 made revocation the ONLY control an enrolment has —
    # it never expires — so a registry that could only be edited and redeployed would make that
    # control unbuildable as anything but a manual out-of-band task.
    #
    # `gateway_credential_encrypted` is ENCRYPTED, not hashed, and is the one value in this
    # service that must be: the provider PRESENTS it to the tenant's gateway on every support
    # request. Everything else the catalog holds it only ever recognises. See `crypto.py` for
    # what happens with no key configured.
    """
    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id                    TEXT PRIMARY KEY,
        display_name                 TEXT NOT NULL DEFAULT '',
        gateway_url                  TEXT NOT NULL DEFAULT '',
        gateway_credential_encrypted TEXT NOT NULL DEFAULT '',
        enrolment_id                 TEXT NOT NULL DEFAULT '',
        enrolled_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
        enrolled_by                  TEXT NOT NULL DEFAULT ''
    )
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
        self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=10, init=_init_connection)
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
