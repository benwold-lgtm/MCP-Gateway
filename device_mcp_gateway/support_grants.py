# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Storage for ADR-0017's support-grant flow (slice 0 of the build).

ADR-0013's provider plane trusted a claim the *provider's* IdP minted (`grants.py`, removed
wholesale in `ece1c75`). ADR-0017 inverts who mints: a provider operator raises a **pending
support request** here, on the tenant's own gateway; a tenant administrator approves or rejects
it; on approval, a **support grant** is minted and its bearer credential is delivered — exactly
once — to whichever session is polling the request it came from. Nothing here trusts a second
issuer. This module holds the two pieces of state that flow needs.

**Two stores, not one state machine**, for the same reason `write_planned.py` (ADR-0022) keeps
its proposal and grant stores separate: they diverge on lookup key, lifetime, and reader.

- `PendingSupportRequestStore` — keyed by an opaque request id, short-lived, polled by the
  *raising* session until a tenant admin decides it. Delivery is one-shot: the first successful
  poll after approval or rejection consumes and deletes the record (ADR-0017 §7 — "a pending
  request that cannot be delivered is lost," never re-servable to a second poll either).
- `SupportGrantStore` — keyed by the grant id the minted bearer carries. Unlike
  `write_planned.WritePlannedGrantStore`'s `check_and_consume` (a single-use redemption at
  Apply), a support grant is **checked live on every request that presents its bearer**,
  potentially many times over its whole window (§2: "the credential is valid for its window,"
  not spent once) — so this store's `check` never consumes anything; only `revoke` mutates a
  live grant, and only a human pressing revoke does that (§8).

Modeled directly on `write_planned.py`'s own shape (itself modeled on `breakglass.py`): a
`Protocol` plus `InMemory*`/`Redis*` implementations, the latter falling back to the in-memory
one (`degraded=True`) on any Redis exception rather than failing the request that reached for
it. Request ids are `secrets.token_urlsafe(24)` — the same CSPRNG-with-no-structure discipline
`write_planned.py` already established, and exactly what ADR-0017 §7 calls the request
identifier: "a capability... generated from a CSPRNG... not a sequence, timestamp, counter, or
operator-derived value."

This module knows nothing about tokens, HTTP, or how a credential is verified — it persists
pending requests and grants, and a caller (the API layer, and later the credential-minting/
verification code) decides what to do with them. That split mirrors `write_planned.py`'s own
separation from `api/write_planned.py`.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, replace
from typing import Any, Literal, Optional, Protocol

from loguru import logger

from device_mcp_gateway.shared.keys import KEYS

#: Why a poll or a grant check did not return "ok", named rather than left for the caller to
#: infer from a bare `None` — the same discipline `write_planned.GrantCheckReason` already
#: established for this codebase's other grant store.
RequestPollReason = Literal["not_found", "pending", "rejected"]
GrantCheckReason = Literal["not_found", "expired", "revoked"]


@dataclass(frozen=True)
class PendingSupportRequest:
    """A provider operator's raised request, awaiting a tenant administrator's decision.

    `provider_subject` is attribution only (ADR-0017 §2: "the provider operator's identity,
    for attribution only — it authorizes nothing") and is also the ONLY subject the poll below
    will ever deliver a decision to — a mismatch reads as not-found, never "found but not
    yours" (§7's resolved polling question)."""

    request_id: str
    provider_subject: str
    requested_scopes: frozenset[str]
    justification: str
    created_at: float
    expires_at: float
    #: True when a Redis-backed store could not reach shared state and answered from
    #: process-local memory instead (same meaning as `write_planned.PendingProposal.degraded`).
    degraded: bool = False


@dataclass(frozen=True)
class RequestPollResult:
    """What a poll of a pending request answers with. `credential` is present exactly once —
    the first successful poll after approval consumes it, and the record is deleted whether
    the outcome was approval or rejection, per this module's one-shot-delivery contract."""

    status: Optional[Literal["pending", "approved", "rejected"]]
    reason: Optional[RequestPollReason] = None
    grant_id: Optional[str] = None
    credential: Optional[str] = None
    degraded: bool = False


@dataclass(frozen=True)
class SupportGrant:
    """A live, tenant-minted grant a provider operator's bearer credential carries the id of.

    `self_issued` marks a grant minted under a tenant's standing-consent setting (§3) rather
    than an explicit per-request approval — the mechanism and every other field are identical
    either way; only the audit trail (slice 5) needs to tell the two apart. `step_up_verified`
    records whether the tenant administrator who approved it (or, for a self-issued grant, the
    operator's own session) was in a step-up-verified session — recorded, never required,
    per §7: a tenant whose IdP cannot express `acr` still gets an honest record instead of a
    silent gap."""

    id: str
    provider_subject: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    step_up_verified: bool = False
    self_issued: bool = False
    revoked_at: Optional[float] = None
    degraded: bool = False


@dataclass(frozen=True)
class GrantCheckResult:
    ok: bool
    reason: Optional[GrantCheckReason] = None
    grant: Optional[SupportGrant] = None
    degraded: bool = False


class PendingSupportRequestStore(Protocol):
    async def create(
        self, *, provider_subject: str, requested_scopes: frozenset[str], justification: str, ttl_seconds: int
    ) -> str:
        """Persist a request awaiting a tenant admin's decision. Returns its opaque id."""
        ...

    async def get(self, request_id: str) -> Optional[PendingSupportRequest]:
        """The request, or None if it never existed, already expired, or was already
        decided-and-delivered. Does not consume — for a reviewer inspecting it, not for the
        one-shot delivery poll below."""
        ...

    async def list_pending(self) -> list[PendingSupportRequest]:
        """Every request still awaiting a decision — what the tenant console's inbox reads.
        A request leaves this list the moment it is decided (approved or rejected), not only
        once delivered — the reviewer already acted; showing it again would look undone."""
        ...

    async def mark_approved(self, request_id: str, *, grant_id: str, credential: str) -> bool:
        """Transition a pending request to approved, attaching the minted grant id and its
        one-time-deliverable bearer credential. False if the request was not found or was not
        still pending (already decided, or expired) — guards against a double-approve race."""
        ...

    async def mark_rejected(self, request_id: str) -> bool:
        """Transition a pending request to rejected. False under the same conditions as
        `mark_approved`."""
        ...

    async def poll(self, request_id: str, *, provider_subject: str) -> RequestPollResult:
        """The raising session's own view: still pending, or a one-time delivery of the
        decision. `provider_subject` must match the request's own — anything else reads as
        `not_found`, never revealing that a *different* operator's request exists (§7).

        Consumes on delivery: after this returns `approved` or `rejected` once, the request no
        longer exists — a second poll for the same id gets `not_found`, exactly like it never
        happened. This is the mechanism, not a side effect of it."""
        ...


class SupportGrantStore(Protocol):
    async def issue(
        self,
        *,
        provider_subject: str,
        scopes: frozenset[str],
        ttl_seconds: int,
        step_up_verified: bool = False,
        self_issued: bool = False,
    ) -> SupportGrant:
        """Mint a live grant. Returns it with a fresh, unguessable `id` — the id a Tier-0
        bearer's payload carries and this store is later keyed on."""
        ...

    async def check(self, grant_id: str) -> GrantCheckResult:
        """Live validity check — called on every request a Tier-0/Tier-1 bearer authenticates,
        not once at redemption. Never mutates anything; only `revoke` does."""
        ...

    async def revoke(self, grant_id: str) -> GrantCheckResult:
        """End a live grant early (ADR-0017 §8). Idempotent: revoking an already-revoked or
        already-expired grant is reported via `reason`, not an exception — a tenant admin
        clicking revoke twice must never see an error for the second click."""
        ...


class InMemoryPendingSupportRequestStore:
    """Per-process store for embedded mode, tests, and the Redis fallback."""

    def __init__(self) -> None:
        self._by_id: dict[str, dict[str, Any]] = {}

    async def create(
        self, *, provider_subject: str, requested_scopes: frozenset[str], justification: str, ttl_seconds: int
    ) -> str:
        now = time.time()
        request_id = secrets.token_urlsafe(24)
        self._by_id[request_id] = {
            "provider_subject": provider_subject,
            "requested_scopes": requested_scopes,
            "justification": justification,
            "created_at": now,
            "expires_at": now + ttl_seconds,
            "status": "pending",
            "grant_id": None,
            "credential": None,
        }
        return request_id

    def _live(self, request_id: str) -> Optional[dict[str, Any]]:
        row = self._by_id.get(request_id)
        if row is None:
            return None
        if time.time() >= row["expires_at"]:
            # Lazy expiry, same as InMemoryPendingProposalStore: nothing sweeps this store in
            # the background, so a stale entry is only ever noticed (and dropped) here.
            del self._by_id[request_id]
            return None
        return row

    async def get(self, request_id: str) -> Optional[PendingSupportRequest]:
        row = self._live(request_id)
        if row is None or row["status"] != "pending":
            return None
        return _request_from_row(request_id, row)

    async def list_pending(self) -> list[PendingSupportRequest]:
        # Snapshot the ids first: `_live` may delete expired entries as it goes, and mutating
        # a dict while iterating it raises.
        out = []
        for request_id in list(self._by_id):
            row = self._live(request_id)
            if row is not None and row["status"] == "pending":
                out.append(_request_from_row(request_id, row))
        return out

    async def mark_approved(self, request_id: str, *, grant_id: str, credential: str) -> bool:
        row = self._live(request_id)
        if row is None or row["status"] != "pending":
            return False
        row["status"] = "approved"
        row["grant_id"] = grant_id
        row["credential"] = credential
        return True

    async def mark_rejected(self, request_id: str) -> bool:
        row = self._live(request_id)
        if row is None or row["status"] != "pending":
            return False
        row["status"] = "rejected"
        return True

    async def poll(self, request_id: str, *, provider_subject: str) -> RequestPollResult:
        row = self._live(request_id)
        if row is None or row["provider_subject"] != provider_subject:
            return RequestPollResult(status=None, reason="not_found")
        if row["status"] == "pending":
            return RequestPollResult(status="pending", reason="pending")
        # Decided — deliver once, then the request is gone.
        del self._by_id[request_id]
        if row["status"] == "rejected":
            return RequestPollResult(status="rejected", reason="rejected")
        return RequestPollResult(status="approved", grant_id=row["grant_id"], credential=row["credential"])


class InMemorySupportGrantStore:
    """Per-process store for embedded mode, tests, and the Redis fallback."""

    def __init__(self) -> None:
        self._by_id: dict[str, SupportGrant] = {}

    async def issue(
        self,
        *,
        provider_subject: str,
        scopes: frozenset[str],
        ttl_seconds: int,
        step_up_verified: bool = False,
        self_issued: bool = False,
    ) -> SupportGrant:
        now = time.time()
        grant = SupportGrant(
            id=secrets.token_urlsafe(24),
            provider_subject=provider_subject,
            scopes=scopes,
            issued_at=now,
            expires_at=now + ttl_seconds,
            step_up_verified=step_up_verified,
            self_issued=self_issued,
        )
        self._by_id[grant.id] = grant
        return grant

    async def check(self, grant_id: str) -> GrantCheckResult:
        grant = self._by_id.get(grant_id)
        if grant is None:
            return GrantCheckResult(ok=False, reason="not_found")
        if grant.revoked_at is not None:
            return GrantCheckResult(ok=False, reason="revoked", grant=grant)
        if time.time() >= grant.expires_at:
            del self._by_id[grant_id]
            return GrantCheckResult(ok=False, reason="expired")
        return GrantCheckResult(ok=True, grant=grant)

    async def revoke(self, grant_id: str) -> GrantCheckResult:
        grant = self._by_id.get(grant_id)
        if grant is None:
            return GrantCheckResult(ok=False, reason="not_found")
        if grant.revoked_at is not None:
            return GrantCheckResult(ok=False, reason="revoked", grant=grant)
        if time.time() >= grant.expires_at:
            del self._by_id[grant_id]
            return GrantCheckResult(ok=False, reason="expired")
        revoked = replace(grant, revoked_at=time.time())
        self._by_id[grant_id] = revoked
        return GrantCheckResult(ok=True, grant=revoked)


class RedisPendingSupportRequestStore:
    """Store shared across gateway replicas, so a tenant admin's approval and the provider
    operator's poll agree regardless of which replica each lands on.

    Falls back to an in-process store on any Redis error — a request that vanished mid-review
    because of a Redis blip would silently discard a decision a human was about to make. The
    fallback keeps the flow alive on the replica that answers it, at the cost of invisibility
    to any other replica until Redis returns (same trade `write_planned.py` already accepts).
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client
        self._fallback = InMemoryPendingSupportRequestStore()

    async def create(
        self, *, provider_subject: str, requested_scopes: frozenset[str], justification: str, ttl_seconds: int
    ) -> str:
        try:
            return await self._create(
                provider_subject=provider_subject,
                requested_scopes=requested_scopes,
                justification=justification,
                ttl_seconds=ttl_seconds,
            )
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support request store fell back to process-local state: {exc}")
            return await self._fallback.create(
                provider_subject=provider_subject,
                requested_scopes=requested_scopes,
                justification=justification,
                ttl_seconds=ttl_seconds,
            )

    async def _create(
        self, *, provider_subject: str, requested_scopes: frozenset[str], justification: str, ttl_seconds: int
    ) -> str:
        now = time.time()
        request_id = secrets.token_urlsafe(24)
        key = KEYS.support_request(request_id)
        pipe = self._r.pipeline(transaction=True)
        pipe.hset(
            key,
            mapping={
                "provider_subject": provider_subject,
                "requested_scopes": ",".join(sorted(requested_scopes)),
                "justification": justification,
                "created_at": str(now),
                "expires_at": str(now + ttl_seconds),
                "status": "pending",
                "grant_id": "",
                "credential": "",
            },
        )
        pipe.expire(key, ttl_seconds)
        # Indexed here, not derived later: there is no Redis primitive for "every hash key
        # matching a pattern" that is safe to run in production (KEYS/SCAN over the whole
        # keyspace), so the pending-list index is maintained alongside the record itself.
        pipe.sadd(KEYS.support_pending_index, request_id)
        await pipe.execute()
        return request_id

    async def get(self, request_id: str) -> Optional[PendingSupportRequest]:
        try:
            return await self._get(request_id)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support request store fell back to process-local state: {exc}")
            req = await self._fallback.get(request_id)
            return replace(req, degraded=True) if req is not None else None

    async def _get(self, request_id: str) -> Optional[PendingSupportRequest]:
        raw = _decode(await self._r.hgetall(KEYS.support_request(request_id)))
        if not raw or raw.get("status") != "pending":
            return None
        expires_at = float(raw["expires_at"])
        if time.time() >= expires_at:
            return None
        return PendingSupportRequest(
            request_id=request_id,
            provider_subject=raw["provider_subject"],
            requested_scopes=frozenset(s for s in raw["requested_scopes"].split(",") if s),
            justification=raw["justification"],
            created_at=float(raw["created_at"]),
            expires_at=expires_at,
        )

    async def list_pending(self) -> list[PendingSupportRequest]:
        try:
            return await self._list_pending()
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support request store fell back to process-local state: {exc}")
            return [replace(r, degraded=True) for r in await self._fallback.list_pending()]

    async def _list_pending(self) -> list[PendingSupportRequest]:
        index_key = KEYS.support_pending_index
        member_bytes = await self._r.smembers(index_key)
        members = [m.decode() if isinstance(m, bytes) else m for m in member_bytes]
        out = []
        stale = []
        for request_id in members:
            request = await self._get(request_id)
            if request is None:
                # The hash's own TTL already reaped it (or a decision moved it out of
                # "pending") — the index just hasn't caught up. Self-heal rather than carry
                # a growing set of dead members forward.
                stale.append(request_id)
                continue
            out.append(request)
        if stale:
            await self._r.srem(index_key, *stale)
        return out

    async def mark_approved(self, request_id: str, *, grant_id: str, credential: str) -> bool:
        try:
            return await self._decide(request_id, status="approved", grant_id=grant_id, credential=credential)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support request store fell back to process-local state: {exc}")
            return await self._fallback.mark_approved(request_id, grant_id=grant_id, credential=credential)

    async def mark_rejected(self, request_id: str) -> bool:
        try:
            return await self._decide(request_id, status="rejected")
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support request store fell back to process-local state: {exc}")
            return await self._fallback.mark_rejected(request_id)

    async def _decide(self, request_id: str, *, status: str, grant_id: str = "", credential: str = "") -> bool:
        key = KEYS.support_request(request_id)
        # HSETNX on a field absent until the first decision — the same race-winner primitive
        # `write_planned.RedisWritePlannedGrantStore._check_and_consume` already uses for
        # `consumed_at`. A concurrent double-decide (two admins clicking at once) can only
        # ever have one winner; the loser's HSETNX simply returns 0, no transaction/retry
        # machinery needed.
        won = await self._r.hsetnx(key, "decided_at", str(time.time()))
        if not won:
            return False
        raw = _decode(await self._r.hgetall(key))
        # Won the race, but the request may have expired in the same instant — the TTL reaps
        # the key on its own clock, not ours, so a decision that lands in that narrow window
        # must not stick even though it "won".
        if not raw or raw.get("status") != "pending" or time.time() >= float(raw.get("expires_at", 0)):
            return False
        pipe = self._r.pipeline(transaction=True)
        pipe.hset(key, mapping={"status": status, "grant_id": grant_id, "credential": credential})
        # Decided — out of the tenant's pending inbox immediately, not just once delivered.
        pipe.srem(KEYS.support_pending_index, request_id)
        await pipe.execute()
        return True

    async def poll(self, request_id: str, *, provider_subject: str) -> RequestPollResult:
        try:
            return await self._poll(request_id, provider_subject=provider_subject)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support request store fell back to process-local state: {exc}")
            result = await self._fallback.poll(request_id, provider_subject=provider_subject)
            return replace(result, degraded=True)

    async def _poll(self, request_id: str, *, provider_subject: str) -> RequestPollResult:
        key = KEYS.support_request(request_id)
        raw = _decode(await self._r.hgetall(key))
        if not raw or raw.get("provider_subject") != provider_subject or time.time() >= float(raw.get("expires_at", 0)):
            return RequestPollResult(status=None, reason="not_found")
        status = raw["status"]
        if status == "pending":
            return RequestPollResult(status="pending", reason="pending")
        await self._r.delete(key)
        if status == "rejected":
            return RequestPollResult(status="rejected", reason="rejected")
        return RequestPollResult(status="approved", grant_id=raw["grant_id"], credential=raw["credential"])


class RedisSupportGrantStore:
    """Store shared across gateway replicas, so a check or a revoke on any of them agrees.

    Falls back to an in-process store on any Redis error, degrading the same way
    `RedisBreakGlassActivity`/`RedisWritePlannedGrantStore` do — a grant minted or revoked
    during a Redis outage is invisible to every other replica until it returns. Acceptable for
    the same reason the fallback exists at all: refusing every check outright because Redis
    hiccuped would end every live support session mid-flight, which is worse than a narrowed,
    logged, temporary window.
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client
        self._fallback = InMemorySupportGrantStore()

    async def issue(
        self,
        *,
        provider_subject: str,
        scopes: frozenset[str],
        ttl_seconds: int,
        step_up_verified: bool = False,
        self_issued: bool = False,
    ) -> SupportGrant:
        try:
            return await self._issue(
                provider_subject=provider_subject,
                scopes=scopes,
                ttl_seconds=ttl_seconds,
                step_up_verified=step_up_verified,
                self_issued=self_issued,
            )
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support grant store fell back to process-local state: {exc}")
            grant = await self._fallback.issue(
                provider_subject=provider_subject,
                scopes=scopes,
                ttl_seconds=ttl_seconds,
                step_up_verified=step_up_verified,
                self_issued=self_issued,
            )
            return replace(grant, degraded=True)

    async def _issue(
        self,
        *,
        provider_subject: str,
        scopes: frozenset[str],
        ttl_seconds: int,
        step_up_verified: bool,
        self_issued: bool,
    ) -> SupportGrant:
        now = time.time()
        grant_id = secrets.token_urlsafe(24)
        key = KEYS.support_grant(grant_id)
        pipe = self._r.pipeline(transaction=True)
        pipe.hset(
            key,
            mapping={
                "provider_subject": provider_subject,
                "scopes": ",".join(sorted(scopes)),
                "issued_at": str(now),
                "expires_at": str(now + ttl_seconds),
                "step_up_verified": "1" if step_up_verified else "0",
                "self_issued": "1" if self_issued else "0",
                "revoked_at": "",
            },
        )
        pipe.expire(key, ttl_seconds)
        await pipe.execute()
        return SupportGrant(
            id=grant_id,
            provider_subject=provider_subject,
            scopes=scopes,
            issued_at=now,
            expires_at=now + ttl_seconds,
            step_up_verified=step_up_verified,
            self_issued=self_issued,
        )

    async def check(self, grant_id: str) -> GrantCheckResult:
        try:
            return await self._check(grant_id)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support grant store fell back to process-local state: {exc}")
            result = await self._fallback.check(grant_id)
            return replace(result, degraded=True)

    async def _check(self, grant_id: str) -> GrantCheckResult:
        raw = _decode(await self._r.hgetall(KEYS.support_grant(grant_id)))
        if not raw:
            return GrantCheckResult(ok=False, reason="not_found")
        grant = _grant_from_raw(grant_id, raw)
        if grant.revoked_at is not None:
            return GrantCheckResult(ok=False, reason="revoked", grant=grant)
        if time.time() >= grant.expires_at:
            return GrantCheckResult(ok=False, reason="expired")
        return GrantCheckResult(ok=True, grant=grant)

    async def revoke(self, grant_id: str) -> GrantCheckResult:
        try:
            return await self._revoke(grant_id)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"support grant store fell back to process-local state: {exc}")
            result = await self._fallback.revoke(grant_id)
            return replace(result, degraded=True)

    async def _revoke(self, grant_id: str) -> GrantCheckResult:
        key = KEYS.support_grant(grant_id)
        raw = _decode(await self._r.hgetall(key))
        if not raw:
            return GrantCheckResult(ok=False, reason="not_found")
        grant = _grant_from_raw(grant_id, raw)
        if grant.revoked_at is not None:
            return GrantCheckResult(ok=False, reason="revoked", grant=grant)
        if time.time() >= grant.expires_at:
            return GrantCheckResult(ok=False, reason="expired")
        now = time.time()
        await self._r.hset(key, "revoked_at", str(now))
        return GrantCheckResult(ok=True, grant=replace(grant, revoked_at=now))


def _request_from_row(request_id: str, row: dict[str, Any]) -> PendingSupportRequest:
    return PendingSupportRequest(
        request_id=request_id,
        provider_subject=row["provider_subject"],
        requested_scopes=row["requested_scopes"],
        justification=row["justification"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


def _grant_from_raw(grant_id: str, raw: dict[str, str]) -> SupportGrant:
    return SupportGrant(
        id=grant_id,
        provider_subject=raw["provider_subject"],
        scopes=frozenset(s for s in raw["scopes"].split(",") if s),
        issued_at=float(raw["issued_at"]),
        expires_at=float(raw["expires_at"]),
        step_up_verified=raw.get("step_up_verified") == "1",
        self_issued=raw.get("self_issued") == "1",
        revoked_at=float(raw["revoked_at"]) if raw.get("revoked_at") else None,
    )


def _decode(raw: dict) -> dict[str, str]:
    """redis-py may hand back `bytes` keys/values depending on client config; normalize once."""
    return {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v) for k, v in raw.items()
    }


def pending_support_request_store(app_state: Any) -> PendingSupportRequestStore:
    """The app's pending-request store, creating a process-local one if nothing was wired.

    Same reasoning as `write_planned.pending_proposal_store`: an app built without the wiring
    (a test, an embedded host built directly) still gets a working store rather than an
    AttributeError."""
    store = getattr(app_state, "support_requests", None)
    if store is None:
        store = InMemoryPendingSupportRequestStore()
        try:
            app_state.support_requests = store
        except Exception:  # noqa: BLE001 — a read-only fake state object is not a failure
            pass
    return store


def support_grant_store(app_state: Any) -> SupportGrantStore:
    """The app's grant store, creating a process-local one if nothing was wired."""
    store = getattr(app_state, "support_grants", None)
    if store is None:
        store = InMemorySupportGrantStore()
        try:
            app_state.support_grants = store
        except Exception:  # noqa: BLE001 — a read-only fake state object is not a failure
            pass
    return store
