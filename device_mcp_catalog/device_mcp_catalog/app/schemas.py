# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Request/response shapes for device-type curation (ADR-0020 §1)."""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Literal, Optional

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
    #:
    #: NOT a place to put a provider-curated spec document, and not somewhere an absolute
    #: URL can be smuggled in later: ADR-0020 §4a settles that a spec the *provider*
    #: curates is snapshotted into the version record as content, because §4's version
    #: pinning and a live reference are mutually exclusive. `spec_path` is the other
    #: mechanism — the tenant's own device, fetched live and refreshed on
    #: `registry.spec_cache_ttl` — and the two must not be collapsed.
    spec_path: Optional[str] = None
    auth_kind: AuthKind = "none"
    fingerprint_policy: Optional[FingerprintPolicy] = None
    #: Free-text note on what changed in this version — surfaced to a reviewer/tenant
    #: deciding whether to accept an upgrade offer (slice 5), not machine-parsed.
    changelog: Optional[str] = None
    #: What this version's shape is DECLARED to imply — hand-entered by the curator as a
    #: list of `{"name", "method", "schema"}` dicts (the same shape
    #: `device_mcp_gateway.core.manifest_diff`'s tool-diff classifier reads). Never
    #: independently verified: the catalog has no tenant base_url to fetch a live spec
    #: against, matching `DeviceConfig.declared_name`'s "self-reported, never measured"
    #: framing on the gateway side. `None` when the curator hasn't supplied one — the
    #: upgrade-offer diff (slice 5) treats that as "no data to diff", a distinct condition
    #: from "diffed and found no changes".
    tool_set: Optional[list[dict[str, Any]]] = None


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


class ToolSetDiff(BaseModel):
    """Mirrors `device_mcp_gateway.core.manifest_diff.ToolSetDiff` field-for-field — the
    shape a caller displaying an upgrade offer already knows how to render. See
    `tool_diff.py` for why this is a deliberate duplicate, not an import, of that module's
    classifier."""

    added: list[str] = []
    removed: list[str] = []
    changed: list[str] = []
    breaking: bool = False
    breaking_reasons: list[str] = []


class UpgradeOffer(BaseModel):
    hostname: str
    device_type_id: uuid.UUID
    slug: str
    claimed_version: int
    current_version: int
    #: `None` when either the claimed or the current version has no declared `tool_set` to
    #: diff — a distinct condition from an empty `ToolSetDiff` (diffed, found no changes).
    diff: Optional[ToolSetDiff] = None


class UpgradeOffersResponse(BaseModel):
    #: Only claims whose current curated version differs from the one they're pinned to.
    #: A device already on the latest curated version is absent here, same as a revoked
    #: assignment is absent from `TenantAssignmentsResponse` — "nothing to offer" reads as
    #: an empty list because it genuinely is one, not because a read failed silently.
    offers: list[UpgradeOffer]
