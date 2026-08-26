# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Data access for device-type curation (ADR-0020 §1). Raw SQL via `asyncpg`, one method per
operation the routes need — no generic CRUD layer, since there are exactly two objects and
four operations in this slice.
"""

from __future__ import annotations

import uuid
from typing import Optional

import asyncpg

from .db import Database
from .schemas import (
    Assignment,
    Claim,
    CreateDeviceType,
    DeviceType,
    DeviceTypeDetail,
    DeviceTypeVersion,
    VersionFields,
)


class SlugAlreadyExists(Exception):
    pass


class DeviceTypeNotFound(Exception):
    pass


class AssignmentNotFound(Exception):
    """Raised on a revoke with nothing active to revoke — either it was never assigned, or
    it already was."""

    pass


class DeviceTypeVersionNotFound(Exception):
    """Raised recording a claim against a (device_type_id, version) pair that was never
    curated — the FK catches it; this just gives the route a named condition to answer
    with instead of a raw constraint-violation 500."""

    pass


def _check_spec_path(fields: VersionFields) -> None:
    """`spec_path` is meaningless for an `mcp` device — the gateway's own
    `registry/validation.py::_validate_upstream` refuses `spec_url` on an mcp registration,
    and a version this repo let through with one set would only fail much later, at claim
    time, for a reason the curator has no visibility into from here."""
    if fields.upstream_kind == "mcp" and fields.spec_path is not None:
        raise ValueError("spec_path must not be set when upstream_kind is 'mcp'")


class DeviceTypeRepo:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def create_device_type(self, fields: CreateDeviceType) -> DeviceTypeDetail:
        _check_spec_path(fields)
        type_id = uuid.uuid4()
        version_id = uuid.uuid4()
        try:
            async with self._db.pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        "INSERT INTO device_types (id, slug, name, description) VALUES ($1, $2, $3, $4)",
                        type_id,
                        fields.slug,
                        fields.name,
                        fields.description,
                    )
                    version_row = await self._insert_version(conn, version_id, type_id, 1, fields)
        except asyncpg.UniqueViolationError as exc:
            raise SlugAlreadyExists(fields.slug) from exc

        return DeviceTypeDetail(
            id=type_id,
            slug=fields.slug,
            name=fields.name,
            description=fields.description,
            created_at=version_row["created_at"],
            latest_version=1,
            versions=[DeviceTypeVersion(**dict(version_row))],
        )

    async def add_version(self, device_type_id: uuid.UUID, fields: VersionFields) -> DeviceTypeVersion:
        _check_spec_path(fields)
        version_id = uuid.uuid4()
        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                # Locks the parent row for the duration of the transaction, serializing
                # concurrent version-adds for the SAME device type against each other — two
                # requests racing to add "the next version" must not both compute the same
                # number. Different device types never contend for this lock.
                type_row = await conn.fetchrow("SELECT id FROM device_types WHERE id = $1 FOR UPDATE", device_type_id)
                if type_row is None:
                    raise DeviceTypeNotFound(device_type_id)
                next_version = await conn.fetchval(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM device_type_versions WHERE device_type_id = $1",
                    device_type_id,
                )
                version_row = await self._insert_version(conn, version_id, device_type_id, next_version, fields)
        return DeviceTypeVersion(**dict(version_row))

    async def list_device_types(self) -> list[DeviceType]:
        rows = await self._db.pool.fetch("""
            SELECT t.id, t.slug, t.name, t.description, t.created_at,
                   COALESCE(MAX(v.version), 0) AS latest_version
            FROM device_types t
            LEFT JOIN device_type_versions v ON v.device_type_id = t.id
            GROUP BY t.id
            ORDER BY t.created_at
            """)
        return [DeviceType(**dict(row)) for row in rows]

    async def get_device_type(self, device_type_id: uuid.UUID) -> Optional[DeviceTypeDetail]:
        type_row = await self._db.pool.fetchrow("SELECT * FROM device_types WHERE id = $1", device_type_id)
        if type_row is None:
            return None
        version_rows = await self._db.pool.fetch(
            "SELECT * FROM device_type_versions WHERE device_type_id = $1 ORDER BY version", device_type_id
        )
        versions = [DeviceTypeVersion(**dict(row)) for row in version_rows]
        return DeviceTypeDetail(
            **dict(type_row),
            latest_version=versions[-1].version if versions else 0,
            versions=versions,
        )

    @staticmethod
    async def _insert_version(
        conn: asyncpg.Connection, version_id: uuid.UUID, device_type_id: uuid.UUID, version: int, fields: VersionFields
    ) -> asyncpg.Record:
        return await conn.fetchrow(
            """
            INSERT INTO device_type_versions
                (id, device_type_id, version, transport, upstream_kind, upstream_transport,
                 spec_path, auth_kind, fingerprint_policy, changelog)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            """,
            version_id,
            device_type_id,
            version,
            fields.transport,
            fields.upstream_kind,
            fields.upstream_transport,
            fields.spec_path,
            fields.auth_kind,
            fields.fingerprint_policy,
            fields.changelog,
        )


class AssignmentRepo:
    """ADR-0020 §2: assignment is an offer, written to provider-plane storage only. It never
    reaches a tenant's own registry — that's the claim flow (slice 4), and it lives entirely
    outside this service."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def assign(self, device_type_id: uuid.UUID, tenant_id: str, assigned_by: str) -> Assignment:
        assignment_id = uuid.uuid4()
        try:
            row = await self._db.pool.fetchrow(
                """
                INSERT INTO assignments (id, device_type_id, tenant_id, assigned_by)
                VALUES ($1, $2, $3, $4)
                RETURNING *
                """,
                assignment_id,
                device_type_id,
                tenant_id,
                assigned_by,
            )
        except asyncpg.ForeignKeyViolationError as exc:
            raise DeviceTypeNotFound(device_type_id) from exc
        except asyncpg.UniqueViolationError:
            # Already actively assigned (the partial unique index caught it) — idempotent:
            # re-assigning something already offered is not an error a caller should have
            # to special-case, it just isn't a NEW assignment.
            row = await self._db.pool.fetchrow(
                "SELECT * FROM assignments WHERE device_type_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
                device_type_id,
                tenant_id,
            )
        return Assignment(**dict(row))

    async def revoke(self, device_type_id: uuid.UUID, tenant_id: str) -> None:
        row = await self._db.pool.fetchrow(
            """
            UPDATE assignments SET revoked_at = now()
            WHERE device_type_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            RETURNING id
            """,
            device_type_id,
            tenant_id,
        )
        if row is None:
            raise AssignmentNotFound((device_type_id, tenant_id))

    async def list_for_tenant(self, tenant_id: str) -> list[DeviceType]:
        rows = await self._db.pool.fetch(
            """
            SELECT t.id, t.slug, t.name, t.description, t.created_at,
                   COALESCE(MAX(v.version), 0) AS latest_version
            FROM assignments a
            JOIN device_types t ON t.id = a.device_type_id
            LEFT JOIN device_type_versions v ON v.device_type_id = t.id
            WHERE a.tenant_id = $1 AND a.revoked_at IS NULL
            GROUP BY t.id
            ORDER BY t.created_at
            """,
            tenant_id,
        )
        return [DeviceType(**dict(row)) for row in rows]


class ClaimRepo:
    """ADR-0020 §4: records which device-type version a tenant's claimed device came from —
    the baseline slice 5's upgrade-offer diff reads. Deliberately NOT the same table as
    `assignments`: an assignment is an offer that can be revoked with nothing ever claimed
    against it, and a claim can outlive the assignment that produced it (revoking an offer
    does not un-register the tenant's already-claimed device, ADR-0020 §2)."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def record_claim(self, device_type_id: uuid.UUID, version: int, tenant_id: str, hostname: str) -> Claim:
        claim_id = uuid.uuid4()
        try:
            row = await self._db.pool.fetchrow(
                """
                INSERT INTO claims (id, device_type_id, version, tenant_id, hostname)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, hostname) DO UPDATE
                    SET device_type_id = EXCLUDED.device_type_id,
                        version = EXCLUDED.version,
                        claimed_at = now()
                RETURNING *
                """,
                claim_id,
                device_type_id,
                version,
                tenant_id,
                hostname,
            )
        except asyncpg.ForeignKeyViolationError as exc:
            raise DeviceTypeVersionNotFound((device_type_id, version)) from exc
        return Claim(**dict(row))
