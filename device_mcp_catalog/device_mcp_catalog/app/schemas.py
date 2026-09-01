# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Request/response shapes for device-type curation (ADR-0020 §1)."""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

UpstreamKind = Literal["openapi", "mcp"]
UpstreamTransport = Literal["http", "sse"]
AuthKind = Literal["none", "api_key", "oauth2"]
FingerprintPolicy = Literal["warn", "enforce"]
#: ADR-0020 §4c — who supplies the device's address. See `VersionFields.host_source`.
HostSource = Literal["tenant", "provider_fixed"]


class VersionFields(BaseModel):
    """The template fields a version carries — everything the claim flow (slice 4) will
    combine with a tenant's `hostname`/credential to register a real device.

    This docstring used to end: *"Deliberately excludes `hostname`/`base_url`/credential:
    those are the tenant's half (ADR-0020 §2), never the provider's to supply here."*
    **ADR-0020 §4c narrows that**, and the rule is restated rather than deleted because the
    exception is narrow and the reason for the original is still live:

    * `hostname` and the credential **value** remain the tenant's half, without exception.
      §5 — the catalog carries no secrets — is untouched.
    * `base_url` is the tenant's half *by default* (`host_source == "tenant"`). A type may
      declare `host_source == "provider_fixed"` and supply `fixed_base_url` when the address
      is genuinely provider knowledge — a provider-hosted appliance image, a normalised front
      end the tenant authenticates to with their own key. That is **not** a §6
      provider-operated service: the provider mints nothing and holds nothing per tenant.

    Why the sentence had to be revised in the same commit that added the field: it was a
    *stated rule*, not an omission, so leaving it would not have made this docstring
    incomplete — it would have made it **wrong**, from the moment the field shipped, with
    nothing to tell a reader which of two contradicting sources was current. §7a is this
    record's own precedent for a written precondition that quietly became false.
    """

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
    #:
    #: THE JUSTIFICATION ABOVE EXPIRES. "No tenant base_url to fetch a live spec against" is
    #: true only while a version holds no spec content of its own. ADR-0020 §4b: once a
    #: version carries a curated spec document, its tool set is DERIVED from that snapshot,
    #: not declared here, and the §4 upgrade diff then compares two measured tool sets
    #: instead of two curator assertions. A curator-supplied declaration that survives
    #: alongside it takes a different field name, so nothing inherits this premise by
    #: association. Versions carrying only `spec_path` keep this field exactly as described.
    tool_set: Optional[list[dict[str, Any]]] = None
    #: WHERE the tenant's API key goes — a property of the appliance's API, not of anyone's
    #: deployment of it. The credential VALUE remains the tenant's half and is never curated
    #: here (ADR-0020 §2); only its position is. A tenant guessing wrong gets a 401 at first
    #: contact, which reads like a bad key rather than a misplaced one.
    #:
    #: Meaningful only when `auth_kind == "api_key"`; supplying either alongside a different
    #: auth_kind is refused rather than ignored, for the reason §4a gave for mutual
    #: exclusivity — a curated field that silently does nothing is one a curator believes is
    #: in effect.
    #:
    #: `None` means the curator has not said, which is NOT the same as "no header": versions
    #: curated before these fields existed have no answer, and the claim flow falls back to
    #: asking the tenant rather than defaulting to something plausible.
    api_key_location: Optional[Literal["header", "query", "cookie"]] = None
    api_key_name: Optional[str] = None
    #: What the provider knows the appliance tolerates. A **recommendation**, and named as
    #: one: it pre-fills the claim form and constrains nothing.
    #:
    #: Deliberately not a ceiling. A tenant may legitimately want to be more conservative,
    #: and a provider enforcing a rate limit on the tenant's OWN gateway would reach across
    #: the plane boundary ADR-0020 §2 keeps — the catalog offers a device type, it does not
    #: operate the tenant's registry.
    recommended_rate_limit_rps: Optional[float] = Field(default=None, gt=0)
    #: ADR-0020 §4a — the provider's own curated OpenAPI document, **snapshotted as text**.
    #:
    #: Text, not JSONB, and this is load-bearing rather than a storage preference. §4b has
    #: the gateway recompute a hash from these bytes at claim time and refuse to trust the
    #: one stored beside them. JSONB normalises key order and whitespace on the way in, so a
    #: document round-tripped through it comes back as different bytes than were curated and
    #: every recomputed hash would disagree with every asserted one — a verification step
    #: that fails constantly is one that gets removed.
    #:
    #: Mutually exclusive with `spec_path`, enforced in `repo.py` (see
    #: `_check_curated_document`). Not "the curated document wins if both are set": a silent
    #: precedence rule is a state a future bug reaches accidentally and which then fails
    #: quietly, which is why `devices:write-planned` is in no role bundle and an unnamed
    #: break-glass entry refuses to start.
    curated_document: Optional[str] = None
    #: ADR-0020 §4c — **who supplies the address**, declared per version and independent of
    #: who supplies the credential. §6's table had only two rows and both of its columns
    #: moved together, so "the provider knows the address, the tenant still brings their own
    #: key" could not be expressed at all.
    #:
    #: `tenant` (the default, and what every existing version is) means the claim flow asks
    #: for `base_url` as it always has. `provider_fixed` means `fixed_base_url` is curated
    #: and the claim flow does not ask.
    #:
    #: Deliberately says nothing about the credential. A `provider_fixed` type whose
    #: `auth_kind` is `api_key` still takes the tenant's own key.
    host_source: HostSource = "tenant"
    #: Populated only when `host_source == "provider_fixed"`, and required then — enforced in
    #: `repo.py` (`_check_host_source`) beside the table's own CHECK, because a declaration
    #: with nothing behind it is a curated field that silently does nothing.
    #:
    #: There is deliberately **no `fixed_spki_pin` here yet.** §4c allows a curated pin only
    #: as a one-time bootstrap seed with no ongoing catalog write path, because a pin the
    #: catalog can keep updating hands the provider the exact laundering path
    #: `device_mcp_gateway.security.fingerprint.decide` exists to prevent ("a changed key does
    #: not re-pin"). Until that seeding is built, a `provider_fixed` type pins on first
    #: contact like any other device — which is correct, just less convenient. Shipping the
    #: field unused would be the very thing the api-key validator below refuses.
    fixed_base_url: Optional[str] = None

    @model_validator(mode="after")
    def _api_key_fields_need_api_key_auth(self) -> "VersionFields":
        if self.auth_kind != "api_key" and (self.api_key_location or self.api_key_name):
            raise ValueError(
                "api_key_location/api_key_name are only meaningful when auth_kind is 'api_key' — "
                "refused rather than ignored, so a curator cannot believe a field is in effect "
                "when nothing reads it (ADR-0020 §2)"
            )
        return self


class CreateDeviceType(VersionFields):
    slug: str = Field(min_length=1, max_length=200, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None


class DeviceTypeVersion(VersionFields):
    id: uuid.UUID
    device_type_id: uuid.UUID
    version: int
    created_at: datetime.datetime
    #: ADR-0020 §4b — sha256 of `curated_document`'s UTF-8 bytes, computed by the repo at
    #: write time and **never accepted from a caller**: a curator who could assert a hash
    #: that disagreed with the content they supplied would make the check meaningless on
    #: arrival. What §4b's claim-time recompute catches is therefore the case nothing else
    #: covers — the two drifting apart *later*, through a bug, a migration or a compromised
    #: curation path.
    #:
    #: NOT the gateway's `spec_hash`, which is a different value computed a different way
    #: (`sha256(str(parsed))[:16]` in `registry/spec_service.py`) for a different purpose.
    #: §4b's rule is that the gateway computes its own from the content and never copies
    #: this one; naming them the same thing is how that rule gets quietly dropped.
    curated_document_sha256: Optional[str] = None


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


class TenantCredential(BaseModel):
    """One entry in the tenant caller table (ADR-0024 §10). **No hash, no secret.**

    A listing answers "how many credentials does this tenant hold, when were they issued, and
    are any still live" — none of which needs the credential itself, and including its hash
    would hand anyone with a candidate token something to compare against.
    """

    id: uuid.UUID
    tenant_id: str
    label: str
    issued_at: datetime.datetime
    issued_by: str
    revoked_at: Optional[datetime.datetime] = None


class TenantCredentialListResponse(BaseModel):
    credentials: list[TenantCredential]


class IssuedCredential(BaseModel):
    """The one response in this service that carries a live secret, returned exactly once.

    There is deliberately no route that can re-show it: a store that can re-show a credential
    is a store that can leak one, and the recovery path is to issue another and revoke this.
    """

    id: uuid.UUID
    tenant_id: str
    label: str
    credential: str


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
