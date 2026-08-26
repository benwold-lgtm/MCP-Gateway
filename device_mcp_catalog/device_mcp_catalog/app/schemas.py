# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Request/response shapes for device-type curation (ADR-0020 §1)."""

from __future__ import annotations

import datetime
import uuid
from typing import Literal, Optional

from pydantic import BaseModel, Field

UpstreamKind = Literal["openapi", "mcp"]
UpstreamTransport = Literal["http", "sse"]
AuthKind = Literal["none", "api_key", "oauth2"]
FingerprintPolicy = Literal["warn", "enforce"]


class VersionFields(BaseModel):
    """The template fields a version carries — everything the claim flow (slice 4) will
    combine with a tenant's `hostname`/`base_url`/credential to register a real device.
    Deliberately excludes `hostname`/`base_url`/credential: those are the tenant's half
    (ADR-0020 §2), never the provider's to supply here."""

    transport: str = "sse"
    upstream_kind: UpstreamKind = "openapi"
    upstream_transport: UpstreamTransport = "http"
    #: Relative to the tenant's base_url at claim time (openapi only) — never an absolute
    #: URL. `None` is required, not just permitted, when `upstream_kind == "mcp"` (an MCP
    #: device has no spec_url at all — see `_validate_upstream` in the gateway's own
    #: `registry/validation.py`); enforced in `repo.py`, not here, so the one validation
    #: lives next to the table constraints it must stay consistent with.
    spec_path: Optional[str] = None
    auth_kind: AuthKind = "none"
    fingerprint_policy: Optional[FingerprintPolicy] = None
    #: Free-text note on what changed in this version — surfaced to a reviewer/tenant
    #: deciding whether to accept an upgrade offer (slice 5), not machine-parsed.
    changelog: Optional[str] = None


class CreateDeviceType(VersionFields):
    slug: str = Field(min_length=1, max_length=200, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None


class DeviceTypeVersion(VersionFields):
    id: uuid.UUID
    device_type_id: uuid.UUID
    version: int
    created_at: datetime.datetime


class DeviceType(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: Optional[str] = None
    created_at: datetime.datetime
    #: The highest version number curated for this type — cheap to compute from the same
    #: query that lists types, and lets a caller show "v3" without a second round trip.
    latest_version: int


class DeviceTypeDetail(DeviceType):
    versions: list[DeviceTypeVersion]


class DeviceTypeListResponse(BaseModel):
    device_types: list[DeviceType]


class AssignRequest(BaseModel):
    """ADR-0020 §2: assignment is an offer, written to provider-plane storage only — it
    never reaches the tenant's own registry. `tenant_id` is the ADR-0019 opaque identifier,
    not a customer name. `assigned_by` is attested by the caller (the console BFF passes
    through its own session's provider subject) rather than derived here — see the
    `assignments` table comment in `db.py` for why."""

    tenant_id: str = Field(min_length=1, max_length=200)
    assigned_by: str = Field(min_length=1, max_length=200)


class Assignment(BaseModel):
    id: uuid.UUID
    device_type_id: uuid.UUID
    tenant_id: str
    assigned_at: datetime.datetime
    assigned_by: str
    revoked_at: Optional[datetime.datetime] = None


class TenantAssignmentsResponse(BaseModel):
    #: What a tenant's claim view (slice 4) reads — the device types currently (not
    #: historically) assigned to this tenant. A revoked assignment is simply absent here,
    #: not a device type with some "revoked" flag on it.
    device_types: list[DeviceType]


class RecordClaim(BaseModel):
    """Slice 4: the BFF calls this immediately after the gateway accepts the tenant's
    registration, to pin down which curated version that device came from. `version` is
    supplied by the caller rather than resolved here — this service has one trusted caller
    (the console BFF), the same trust boundary every other route in this service already
    rests on."""

    tenant_id: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=253)
    version: int = Field(ge=1)


class Claim(BaseModel):
    id: uuid.UUID
    device_type_id: uuid.UUID
    version: int
    tenant_id: str
    hostname: str
    claimed_at: datetime.datetime
