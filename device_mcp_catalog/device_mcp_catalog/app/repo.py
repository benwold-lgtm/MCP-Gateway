# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Data access for device-type curation (ADR-0020 §1). Raw SQL via `asyncpg`, one method per
operation the routes need — no generic CRUD layer, since there are exactly two objects and
four operations in this slice.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Optional

import asyncpg

from . import tool_diff
from .db import Database
from .schemas import (
    Assignment,
    Claim,
    CreateDeviceType,
    DeviceType,
    DeviceTypeDetail,
    DeviceTypeVersion,
    ToolSetDiff,
    UpgradeOffer,
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


def _document_sha256(document: Optional[str]) -> Optional[str]:
    """The hash curation asserts about the bytes it stored (ADR-0020 §4b).

    Computed here rather than accepted from the caller: a curator able to assert a hash that
    disagreed with the content they supplied would make the whole check meaningless on
    arrival. What the claim-time recompute catches is the two drifting apart *later*.

    Full-length hex of the raw UTF-8 bytes, and deliberately not the gateway's `spec_hash`
    (`sha256(str(parsed))[:16]`). Two values, two purposes; §4b's rule is that the gateway
    computes its own and never copies this one, and giving them the same shape is how that
    rule quietly stops being followed.
    """
    if document is None:
        return None
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _check_curated_document(fields: VersionFields) -> None:
    """ADR-0020 §4b: a version carries a curated document or a `spec_path`, never both — and
    a curated document is not accompanied by a curator-declared `tool_set`.

    Explicitly **not** "the curated document wins if both are set". A silent precedence rule
    is a state a future bug reaches accidentally and then fails quietly inside, which is why
    `devices:write-planned` is a member of no role bundle and an unnamed `break_glass: true`
    entry refuses to start rather than falling back. The ambiguity is resolved by the curator
    at write time or not at all.

    The `tool_set` half is §4b's "its stated premise expires" rule, enforced at the only
    moment it can be. `VersionFields.tool_set` justifies being unverified by *"the catalog has
    no tenant base_url to fetch a live spec against"*, which stops being true the moment
    content sits in the row. Deriving the tool set from that content is a separate slice — it
    needs an OpenAPI translator this service deliberately does not have (see `tool_diff.py`
    on why the catalog does not import the gateway package). Until then the honest position is
    to refuse the combination rather than to store a curator assertion beside content that
    contradicts it, which is the expired-premise bug rather than a smaller version of it.
    """
    if fields.curated_document is None:
        return
    if fields.spec_path is not None:
        raise ValueError(
            "a version carries a curated document or a spec_path, never both (ADR-0020 §4b) — "
            "resolve which one this version uses rather than relying on a precedence rule"
        )
    if fields.tool_set is not None:
        raise ValueError(
            "tool_set must not be set on a version carrying a curated document (ADR-0020 §4b): "
            "the declaration's premise — that the catalog has no content to measure — is false "
            "once the content is in the row, and a derived tool set is not built yet"
        )


def _check_host_source(fields: VersionFields) -> None:
    """ADR-0020 §4c: `fixed_base_url` is populated exactly when `host_source` says it is.

    Both directions are errors, and neither is pedantry. A `provider_fixed` type with no
    address is a claim flow with nothing to claim against, discovered by the tenant rather
    than the curator. A `fixed_base_url` sitting under `host_source == "tenant"` is a curated
    field that silently does nothing — the condition
    `_api_key_fields_need_api_key_auth` refuses for the same reason, because a curator who can
    see a value they filled in believes it is in effect.

    Here rather than as a pydantic validator in `schemas.py`, following `_check_spec_path`'s
    stated rule: this one has to stay consistent with a table CHECK constraint, so it lives
    next to the constraint it mirrors.
    """
    if fields.host_source == "provider_fixed":
        if not fields.fixed_base_url:
            raise ValueError(
                "fixed_base_url is required when host_source is 'provider_fixed' (ADR-0020 §4c) — "
                "a host-fixed type with no host is discovered by the tenant, not the curator"
            )
    elif fields.fixed_base_url is not None:
        raise ValueError(
            "fixed_base_url must not be set when host_source is 'tenant' (ADR-0020 §4c) — "
            "refused rather than ignored, so a curator cannot believe a field is in effect "
            "when nothing reads it"
        )


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
        _check_curated_document(fields)
        _check_host_source(fields)
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
        _check_curated_document(fields)
        _check_host_source(fields)
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
                 spec_path, auth_kind, fingerprint_policy, changelog, tool_set,
                 api_key_location, api_key_name, recommended_rate_limit_rps,
                 curated_document, curated_document_sha256, host_source, fixed_base_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
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
            fields.tool_set,
            fields.api_key_location,
            fields.api_key_name,
            fields.recommended_rate_limit_rps,
            fields.curated_document,
            _document_sha256(fields.curated_document),
            fields.host_source,
            fields.fixed_base_url,
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

    async def is_assigned(self, device_type_id: uuid.UUID, tenant_id: str) -> bool:
        """Whether this type is *currently* offered to this tenant (ADR-0020 §7a).

        Deliberately not expressed as `device_type_id in list_for_tenant(...)`: that reads the
        whole offer list to answer a yes/no, and it would drift the moment the list route
        gained a filter this check should not inherit. `revoked_at IS NULL` mirrors
        `list_for_tenant`'s own definition of an active offer — a revoked assignment is absent,
        never a row with a flag on it.
        """
        return bool(
            await self._db.pool.fetchval(
                """
                SELECT 1 FROM assignments
                WHERE device_type_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
                LIMIT 1
                """,
                device_type_id,
                tenant_id,
            )
        )


class TenantCredentialRepo:
    """ADR-0024 §10: the tenant caller table, once it stops being static config.

    ADR-0020 §7a made the catalog authenticate two caller classes but had nothing that could
    *mint* a tenant's credential, so the table lived in `CATALOG_TENANT_TOKENS`. Approving an
    enrolment is the moment one should be issued, which needs an API, which needs a store.

    Credentials are held as hashes. This service recognises them and never presents them, so
    the one-way form costs nothing and means this table is not a set of live secrets.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    async def issue(self, tenant_id: str, *, credential_hash: str, label: str, issued_by: str) -> uuid.UUID:
        credential_id = uuid.uuid4()
        await self._db.pool.execute(
            """
            INSERT INTO tenant_credentials (id, tenant_id, credential_hash, label, issued_by)
            VALUES ($1, $2, $3, $4, $5)
            """,
            credential_id,
            tenant_id,
            credential_hash,
            label,
            issued_by,
        )
        return credential_id

    async def tenant_for(self, credential_hash: str) -> Optional[str]:
        """The tenant a live credential belongs to, or `None`.

        `revoked_at IS NULL` is in the query rather than applied to the result: it matches the
        partial index, and it means a revoked credential is not *found and then rejected* but
        simply absent — the shortest path being the live one, because this runs on every
        request an issued credential makes.
        """
        return await self._db.pool.fetchval(
            "SELECT tenant_id FROM tenant_credentials WHERE credential_hash = $1 AND revoked_at IS NULL",
            credential_hash,
        )

    async def list_for_tenant(self, tenant_id: str, *, include_revoked: bool = False) -> list[dict]:
        """What was issued to a tenant. Never returns a hash: a listing exists to answer "how
        many credentials does this tenant have and when were they issued", and a hash in it
        would be a value to compare against for anyone who obtained a candidate token."""
        rows = await self._db.pool.fetch(
            """
            SELECT id, tenant_id, label, issued_at, issued_by, revoked_at
            FROM tenant_credentials
            WHERE tenant_id = $1 AND ($2 OR revoked_at IS NULL)
            ORDER BY issued_at
            """,
            tenant_id,
            include_revoked,
        )
        return [dict(row) for row in rows]

    async def revoke(self, credential_id: uuid.UUID) -> bool:
        """Idempotent, like every other revoke in this estate: revoking an already-revoked
        credential reports the same outcome rather than an error, because the person clicking
        twice is usually doing so because something is wrong right now."""
        row = await self._db.pool.fetchrow(
            "UPDATE tenant_credentials SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING id",
            credential_id,
        )
        if row is not None:
            return True
        exists = await self._db.pool.fetchval("SELECT 1 FROM tenant_credentials WHERE id = $1", credential_id)
        return bool(exists)

    async def revoke_all_for_tenant(self, tenant_id: str) -> int:
        """Every live credential a tenant holds, at once — what ending an enrolment calls.

        §10: "revoking an enrolment revokes that credential too." Expressed here rather than
        left to the caller to loop, so that ending a relationship cannot half-happen because
        something interrupted a client between two revokes.
        """
        rows = await self._db.pool.fetch(
            "UPDATE tenant_credentials SET revoked_at = now() WHERE tenant_id = $1 AND revoked_at IS NULL RETURNING id",
            tenant_id,
        )
        return len(rows)


class TenantRegistryRepo:
    """ADR-0024 §11: who this provider serves.

    Deliberately a separate repo class from `TenantCredentialRepo` even though both are keyed by
    `tenant_id` and both are written by the same enrolment: they answer different questions, and
    one class doing both would make "list the estate" and "authenticate a caller" share a code
    path that has no reason to stay together.
    """

    def __init__(self, db: Database, codec: Any = None) -> None:
        self._db = db
        self._codec = codec

    def _decrypt(self, stored: str) -> str:
        return self._codec.decrypt(stored) if self._codec is not None else stored

    def _encrypt(self, plaintext: str) -> str:
        return self._codec.encrypt(plaintext) if self._codec is not None else plaintext

    async def enrol(
        self,
        tenant_id: str,
        *,
        display_name: str,
        gateway_url: str,
        gateway_credential: str,
        enrolment_id: str,
        enrolled_by: str,
        credential_hash: str,
        credential_label: str,
    ) -> uuid.UUID:
        """Record the tenant AND issue its catalog credential, in ONE transaction (§11).

        These are the two writes the provider owns, and the point of the section is that they
        cannot half-happen: a registry entry with no credential is a tenant the console lists
        and cannot serve, and a credential with no registry entry is the orphan the provider
        console's compensation logic exists to clean up.

        **The tenant gateway's own enrolment record is NOT in here and cannot be** — it is a
        different system across a plane boundary, which is the whole point of §10's handshake.
        That step stays distributed with compensation, and §11 says so rather than letting
        "approving an enrolment is atomic" over-reach.

        Upserts the registry row: re-enrolling a tenant after a revoke replaces the entry rather
        than failing, since the ordinary way to repair a relationship is to enrol again.
        """
        credential_id = uuid.uuid4()
        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO tenant_credentials (id, tenant_id, credential_hash, label, issued_by)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    credential_id,
                    tenant_id,
                    credential_hash,
                    credential_label,
                    enrolled_by,
                )
                await conn.execute(
                    """
                    INSERT INTO tenants (tenant_id, display_name, gateway_url,
                                         gateway_credential_encrypted, enrolment_id, enrolled_by)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        display_name = EXCLUDED.display_name,
                        gateway_url = EXCLUDED.gateway_url,
                        gateway_credential_encrypted = EXCLUDED.gateway_credential_encrypted,
                        enrolment_id = EXCLUDED.enrolment_id,
                        enrolled_at = now(),
                        enrolled_by = EXCLUDED.enrolled_by
                    """,
                    tenant_id,
                    display_name,
                    gateway_url,
                    self._encrypt(gateway_credential),
                    enrolment_id,
                    enrolled_by,
                )
        return credential_id

    async def list_tenants(self) -> list[dict]:
        """The estate, without secrets. What the provider console's tenant picker reads."""
        rows = await self._db.pool.fetch("""
            SELECT tenant_id, display_name, gateway_url, enrolment_id, enrolled_at, enrolled_by
            FROM tenants ORDER BY enrolled_at
            """)
        return [dict(row) for row in rows]

    async def gateway_credential(self, tenant_id: str) -> Optional[dict]:
        """One tenant's gateway URL and the provider's credential for it, decrypted.

        The only route to a usable secret here, and its own method rather than a field on the
        listing above — a listing is a screen left open, and a credential should be fetched by
        the component that needs it, when it needs it.
        """
        row = await self._db.pool.fetchrow(
            "SELECT tenant_id, gateway_url, gateway_credential_encrypted FROM tenants WHERE tenant_id = $1",
            tenant_id,
        )
        if row is None:
            return None
        return {
            "tenant_id": row["tenant_id"],
            "gateway_url": row["gateway_url"],
            "gateway_credential": self._decrypt(row["gateway_credential_encrypted"]),
        }

    async def set_gateway_credential(self, tenant_id: str, *, gateway_credential: str, enrolment_id: str = "") -> bool:
        """Record the provider's own credential for an already-enrolled tenant's gateway.

        The enrolment handshake cannot supply this to `enrol()`, and the ordering is forced
        rather than chosen: the tenant's catalog credential has to exist *before* the redemption,
        because the redemption is what hands it over, and the provider's credential only exists
        *after* it. So the registry row is created with this column empty and filled in here.

        That intermediate state is real, not a bookkeeping artefact — between those two calls the
        provider genuinely cannot call the tenant back — and `list_tenants()` shows it, which is
        why a redemption that dies at this last step is left visible and repairable by enrolling
        again rather than silently withdrawn.

        Returns False for a tenant with no registry entry: "not enrolled" is a different
        condition from "enrolled with nothing recorded", and a caller that could not tell them
        apart would report a successful write that landed nowhere.
        """
        result = await self._db.pool.execute(
            """
            UPDATE tenants
            SET gateway_credential_encrypted = $2,
                enrolment_id = COALESCE(NULLIF($3, ''), enrolment_id)
            WHERE tenant_id = $1
            """,
            tenant_id,
            self._encrypt(gateway_credential),
            enrolment_id,
        )
        return result.rsplit(" ", 1)[-1] != "0"

    async def withdraw(self, tenant_id: str) -> dict:
        """End the relationship: remove the registry entry AND revoke every live credential, in
        one transaction (§11's property to test).

        Returns what was actually removed, so a caller can tell "ended a live relationship" from
        "there was nothing there" — the same distinction the bulk credential revoke draws.
        """
        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                revoked = await conn.fetch(
                    """
                    UPDATE tenant_credentials SET revoked_at = now()
                    WHERE tenant_id = $1 AND revoked_at IS NULL RETURNING id
                    """,
                    tenant_id,
                )
                removed = await conn.fetchrow("DELETE FROM tenants WHERE tenant_id = $1 RETURNING tenant_id", tenant_id)
        return {"tenant_id": tenant_id, "removed": removed is not None, "credentials_revoked": len(revoked)}


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

    async def list_upgrade_offers(self, tenant_id: str) -> list[UpgradeOffer]:
        """Slice 5: for each of this tenant's claims, compare the `tool_set` DECLARED on
        the version it's pinned to against the one declared on the type's current
        (highest-numbered) version. Never touches the gateway or any live device — this is
        entirely a diff between two rows of curator-entered data."""
        rows = await self._db.pool.fetch(
            """
            SELECT c.hostname, c.device_type_id, t.slug,
                   c.version AS claimed_version, cv.tool_set AS claimed_tool_set,
                   latest.version AS current_version, latest.tool_set AS current_tool_set
            FROM claims c
            JOIN device_types t ON t.id = c.device_type_id
            JOIN device_type_versions cv
                ON cv.device_type_id = c.device_type_id AND cv.version = c.version
            JOIN LATERAL (
                SELECT version, tool_set FROM device_type_versions
                WHERE device_type_id = c.device_type_id
                ORDER BY version DESC LIMIT 1
            ) latest ON true
            WHERE c.tenant_id = $1
            """,
            tenant_id,
        )
        offers: list[UpgradeOffer] = []
        for row in rows:
            if row["current_version"] == row["claimed_version"]:
                continue  # already on the current curated version — nothing to offer
            diff: Optional[ToolSetDiff] = None
            if row["claimed_tool_set"] is not None and row["current_tool_set"] is not None:
                d = tool_diff.diff_tools(row["claimed_tool_set"], row["current_tool_set"])
                diff = ToolSetDiff(
                    added=d.added,
                    removed=d.removed,
                    changed=d.changed,
                    breaking=d.breaking,
                    breaking_reasons=d.breaking_reasons,
                )
            offers.append(
                UpgradeOffer(
                    hostname=row["hostname"],
                    device_type_id=row["device_type_id"],
                    slug=row["slug"],
                    claimed_version=row["claimed_version"],
                    current_version=row["current_version"],
                    diff=diff,
                )
            )
        return offers
