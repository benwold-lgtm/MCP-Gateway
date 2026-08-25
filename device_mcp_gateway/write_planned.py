# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Storage for ADR-0022's Propose/Review/Apply flow.

`caller`'s baseline never gains `devices:write` (ADR-0022's whole point). Instead an agent
*proposes* a device registration/reconfiguration, a human *reviews* it and mints a grant
scoped to that one plan's digest, and the agent *applies* by redeeming the grant. This module
holds the two pieces of state that flow requires — state the gateway has never needed before:
its only prior elevated-grant system (`grants.py`, ADR-0013) was deleted wholesale in PR #139.

**Two stores, not one state machine**, because they diverge on lookup key, lifetime, and
reader — the same reason ADR-0018 §6 itself keeps `plan_digest` (content commitment) and
`plan_token` (validity/age) as separate concepts rather than collapsing them:

- `PendingProposalStore` — keyed by an opaque proposal id, short-lived, read once by the
  reviewer (`GET .../plans/{id}`) and deleted the moment it is approved or rejected.
- `WritePlannedGrantStore` — keyed by the plan digest itself, potentially long-lived when a
  reviewer marks it repeatable (§4), read at Apply.

Neither record carries a hostname or target field. The digest already commits to the whole
canonicalized plan (`shared/canonical_json.compute_digest`), so exact-digest equality already
*is* "the same target, unchanged" — which is exactly the property §4's unattended-reconciliation
bound needs, for free, rather than as separate tracking.

Modeled directly on `breakglass.py`'s `BreakGlassActivity`: a `Protocol` plus `InMemory*`/
`Redis*` implementations, the latter falling back to the in-memory one (`degraded=True`) on any
Redis exception rather than failing the request that reached for it. This mechanism is not the
observability-of-an-emergency-path break-glass is, so the fallback carries a real cost break-glass
does not: a grant issued against a Redis-backed store that a later Apply must read while Redis is
down still degrades to the in-memory fallback within one process, and the same disclaimer
applies — see the class docstrings below.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, replace
from typing import Any, Literal, Optional, Protocol

from loguru import logger

from device_mcp_gateway.shared.keys import KEYS

#: Why a check or consumption failed, named rather than left for the caller to infer from a
#: bare `False` — ADR-0022's own `ERR_PLAN_STALE`-shaped precedent in `api/backup.py` never
#: collapses distinct causes into one, and a caller auditing an Apply refusal needs to say
#: which of these happened, not just that it did.
GrantCheckReason = Literal["not_found", "expired", "subject_mismatch", "consumed"]


@dataclass(frozen=True)
class PendingProposal:
    subject: str
    digest: str
    plan: dict[str, Any]
    created_at: float
    expires_at: float
    #: True when a Redis-backed store could not reach shared state and answered from
    #: process-local memory instead (same meaning as `breakglass.Activity.degraded`): this
    #: proposal may be invisible to a reviewer hitting a different replica.
    degraded: bool = False


@dataclass(frozen=True)
class Grant:
    digest: str
    subject: str
    reviewer_subject: str
    repeatable: bool
    issued_at: float
    expires_at: float
    #: Set only for a single-use grant, only once redeemed. A repeatable grant is never
    #: consumed — its whole purpose is surviving byte-identical reapplication (§4).
    consumed_at: Optional[float] = None
    #: See `PendingProposal.degraded`. A degraded `issue()` means a concurrent Apply routed
    #: to a different replica would not see this grant until Redis returns.
    degraded: bool = False


@dataclass(frozen=True)
class GrantCheckResult:
    ok: bool
    reason: Optional[GrantCheckReason] = None
    #: Present when `ok`, and also on a `"consumed"`/`"subject_mismatch"` refusal — an
    #: audit record naming *who* the grant actually belonged to is worth more than one that
    #: only says the check failed. Absent for `"not_found"`/`"expired"`: there is nothing to
    #: report by then, by construction (Redis has often already reaped the key itself).
    grant: Optional[Grant] = None
    #: See `PendingProposal.degraded`. A degraded single-use consumption is only guaranteed
    #: not-double-spent within this one process until Redis returns — see the class
    #: docstrings on `RedisWritePlannedGrantStore` for the operational consequence.
    degraded: bool = False


class PendingProposalStore(Protocol):
    async def create(self, *, subject: str, digest: str, plan: dict[str, Any], ttl_seconds: int) -> str:
        """Persist a proposal awaiting review. Returns its opaque id."""
        ...

    async def get(self, proposal_id: str) -> Optional[PendingProposal]:
        """The proposal, or None if it never existed, already expired, or was consumed."""
        ...

    async def delete(self, proposal_id: str) -> None:
        """Remove a proposal — called once it is approved or explicitly rejected."""
        ...


class WritePlannedGrantStore(Protocol):
    async def issue(
        self, *, digest: str, subject: str, reviewer_subject: str, repeatable: bool, ttl_seconds: int
    ) -> Grant:
        """Mint a grant scoped to `digest`, redeemable only by `subject` (ADR-0022 step 2)."""
        ...

    async def check_and_consume(self, *, digest: str, subject: str) -> GrantCheckResult:
        """Validate a live grant for `(digest, subject)` and, if single-use, consume it.

        Atomic in the sense that matters: for a single-use grant, whether *this* call is the
        one that consumed it is decided by a single atomic store operation, not by the earlier
        read — closing the same check/write race `_run_restore` closes for restore's apply.
        """
        ...


class InMemoryPendingProposalStore:
    """Per-process store for embedded mode, tests, and the Redis fallback."""

    def __init__(self) -> None:
        self._by_id: dict[str, PendingProposal] = {}

    async def create(self, *, subject: str, digest: str, plan: dict[str, Any], ttl_seconds: int) -> str:
        now = time.time()
        proposal_id = secrets.token_urlsafe(24)
        self._by_id[proposal_id] = PendingProposal(
            subject=subject, digest=digest, plan=plan, created_at=now, expires_at=now + ttl_seconds
        )
        return proposal_id

    async def get(self, proposal_id: str) -> Optional[PendingProposal]:
        proposal = self._by_id.get(proposal_id)
        if proposal is None:
            return None
        if time.time() >= proposal.expires_at:
            # Lazy expiry, same as InMemoryBreakGlassActivity: nothing sweeps this store in
            # the background, so a stale entry is only ever noticed (and dropped) here.
            del self._by_id[proposal_id]
            return None
        return proposal

    async def delete(self, proposal_id: str) -> None:
        self._by_id.pop(proposal_id, None)


class InMemoryWritePlannedGrantStore:
    """Per-process store for embedded mode, tests, and the Redis fallback."""

    def __init__(self) -> None:
        self._by_digest: dict[str, Grant] = {}

    async def issue(
        self, *, digest: str, subject: str, reviewer_subject: str, repeatable: bool, ttl_seconds: int
    ) -> Grant:
        now = time.time()
        grant = Grant(
            digest=digest,
            subject=subject,
            reviewer_subject=reviewer_subject,
            repeatable=repeatable,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        self._by_digest[digest] = grant
        return grant

    async def check_and_consume(self, *, digest: str, subject: str) -> GrantCheckResult:
        grant = self._by_digest.get(digest)
        if grant is None:
            return GrantCheckResult(ok=False, reason="not_found")
        if time.time() >= grant.expires_at:
            del self._by_digest[digest]
            return GrantCheckResult(ok=False, reason="expired")
        if grant.subject != subject:
            return GrantCheckResult(ok=False, reason="subject_mismatch", grant=grant)
        if grant.repeatable:
            return GrantCheckResult(ok=True, grant=grant)
        if grant.consumed_at is not None:
            return GrantCheckResult(ok=False, reason="consumed", grant=grant)
        # No `await` between the lookup above and this write — single-threaded asyncio gives
        # this the same effective atomicity `check_and_consume`'s docstring promises, the way
        # InMemoryBreakGlassActivity's dict mutation already relies on for its own tracker.
        consumed = Grant(**{**grant.__dict__, "consumed_at": time.time()})
        self._by_digest[digest] = consumed
        return GrantCheckResult(ok=True, grant=consumed)


class RedisPendingProposalStore:
    """Store shared across gateway replicas, so a review sees the proposal any of them took.

    Falls back to an in-process store on any Redis error. A proposal that vanished mid-review
    because of a Redis blip would silently discard a plan a human was about to approve — the
    fallback keeps the flow alive on the replica that answers Review, at the cost of that
    proposal being invisible to any other replica until Redis returns.
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client
        self._fallback = InMemoryPendingProposalStore()

    async def create(self, *, subject: str, digest: str, plan: dict[str, Any], ttl_seconds: int) -> str:
        try:
            return await self._create(subject=subject, digest=digest, plan=plan, ttl_seconds=ttl_seconds)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"write_planned proposal store fell back to process-local state: {exc}")
            return await self._fallback.create(subject=subject, digest=digest, plan=plan, ttl_seconds=ttl_seconds)

    async def _create(self, *, subject: str, digest: str, plan: dict[str, Any], ttl_seconds: int) -> str:
        now = time.time()
        proposal_id = secrets.token_urlsafe(24)
        key = KEYS.write_planned_proposal(proposal_id)
        pipe = self._r.pipeline(transaction=True)
        pipe.hset(
            key,
            mapping={
                "subject": subject,
                "digest": digest,
                "plan": json.dumps(plan),
                "created_at": str(now),
                "expires_at": str(now + ttl_seconds),
            },
        )
        pipe.expire(key, ttl_seconds)
        await pipe.execute()
        return proposal_id

    async def get(self, proposal_id: str) -> Optional[PendingProposal]:
        try:
            return await self._get(proposal_id)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"write_planned proposal store fell back to process-local state: {exc}")
            proposal = await self._fallback.get(proposal_id)
            return replace(proposal, degraded=True) if proposal is not None else None

    async def _get(self, proposal_id: str) -> Optional[PendingProposal]:
        raw = await self._r.hgetall(KEYS.write_planned_proposal(proposal_id))
        if not raw:
            return None
        raw = _decode(raw)
        expires_at = float(raw["expires_at"])
        if time.time() >= expires_at:
            # Redis TTL usually beats us to it; this covers the narrow window where our own
            # clock says "expired" a moment before Redis has reaped the key.
            return None
        return PendingProposal(
            subject=raw["subject"],
            digest=raw["digest"],
            plan=json.loads(raw["plan"]),
            created_at=float(raw["created_at"]),
            expires_at=expires_at,
        )

    async def delete(self, proposal_id: str) -> None:
        try:
            await self._r.delete(KEYS.write_planned_proposal(proposal_id))
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"write_planned proposal store fell back to process-local state: {exc}")
            await self._fallback.delete(proposal_id)


class RedisWritePlannedGrantStore:
    """Store shared across gateway replicas, so an Apply on any of them sees the grant.

    Falls back to an in-process store on any Redis error, degrading the same way
    `RedisBreakGlassActivity` does — but unlike break-glass, a grant this fallback mints or
    consumes is invisible to every other replica until Redis returns, which for a single-use
    grant means a second Apply routed to a different replica during the outage would not see
    it as consumed. Acceptable for the same reason the fallback exists at all: refusing every
    Apply outright because Redis hiccuped is worse than a narrowed, logged, temporary window.
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client
        self._fallback = InMemoryWritePlannedGrantStore()

    async def issue(
        self, *, digest: str, subject: str, reviewer_subject: str, repeatable: bool, ttl_seconds: int
    ) -> Grant:
        try:
            return await self._issue(
                digest=digest,
                subject=subject,
                reviewer_subject=reviewer_subject,
                repeatable=repeatable,
                ttl_seconds=ttl_seconds,
            )
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"write_planned grant store fell back to process-local state: {exc}")
            grant = await self._fallback.issue(
                digest=digest,
                subject=subject,
                reviewer_subject=reviewer_subject,
                repeatable=repeatable,
                ttl_seconds=ttl_seconds,
            )
            return replace(grant, degraded=True)

    async def _issue(
        self, *, digest: str, subject: str, reviewer_subject: str, repeatable: bool, ttl_seconds: int
    ) -> Grant:
        now = time.time()
        key = KEYS.write_planned_grant(digest)
        pipe = self._r.pipeline(transaction=True)
        pipe.delete(key)  # a re-approval of the same digest replaces any prior grant cleanly
        pipe.hset(
            key,
            mapping={
                "subject": subject,
                "reviewer_subject": reviewer_subject,
                "repeatable": "1" if repeatable else "0",
                "issued_at": str(now),
                "expires_at": str(now + ttl_seconds),
            },
        )
        pipe.expire(key, ttl_seconds)
        await pipe.execute()
        return Grant(
            digest=digest,
            subject=subject,
            reviewer_subject=reviewer_subject,
            repeatable=repeatable,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )

    async def check_and_consume(self, *, digest: str, subject: str) -> GrantCheckResult:
        try:
            return await self._check_and_consume(digest=digest, subject=subject)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"write_planned grant store fell back to process-local state: {exc}")
            result = await self._fallback.check_and_consume(digest=digest, subject=subject)
            return replace(result, degraded=True)

    async def _check_and_consume(self, *, digest: str, subject: str) -> GrantCheckResult:
        key = KEYS.write_planned_grant(digest)
        raw = await self._r.hgetall(key)
        if not raw:
            return GrantCheckResult(ok=False, reason="not_found")
        raw = _decode(raw)
        expires_at = float(raw["expires_at"])
        if time.time() >= expires_at:
            return GrantCheckResult(ok=False, reason="expired")
        repeatable = raw["repeatable"] == "1"
        stored_subject = raw["subject"]
        consumed_raw = raw.get("consumed_at")

        def _grant(consumed_at: Optional[float]) -> Grant:
            return Grant(
                digest=digest,
                subject=stored_subject,
                reviewer_subject=raw["reviewer_subject"],
                repeatable=repeatable,
                issued_at=float(raw["issued_at"]),
                expires_at=expires_at,
                consumed_at=consumed_at,
            )

        if stored_subject != subject:
            prior_consumed = float(consumed_raw) if consumed_raw else None
            return GrantCheckResult(ok=False, reason="subject_mismatch", grant=_grant(prior_consumed))
        if repeatable:
            return GrantCheckResult(ok=True, grant=_grant(None))
        if consumed_raw:
            return GrantCheckResult(ok=False, reason="consumed", grant=_grant(float(consumed_raw)))

        # The decisive operation: HSETNX only sets the field if it is absent, atomically, and
        # tells us whether *we* were the one who set it. Two concurrent Applies for the same
        # single-use grant race here, not at the HGETALL above — exactly one gets `1`.
        now = time.time()
        won = await self._r.hsetnx(key, "consumed_at", str(now))
        if not won:
            return GrantCheckResult(ok=False, reason="consumed", grant=_grant(None))
        return GrantCheckResult(ok=True, grant=_grant(now))


def _decode(raw: dict) -> dict[str, str]:
    """redis-py may hand back `bytes` keys/values depending on client config; normalize once."""
    return {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v) for k, v in raw.items()
    }


def pending_proposal_store(app_state: Any) -> PendingProposalStore:
    """The app's proposal store, creating a process-local one if nothing was wired.

    Same reasoning as `breakglass._tracker`: an app built without the wiring (a test, an
    embedded host built directly) still gets a working store rather than an AttributeError.
    """
    store = getattr(app_state, "write_planned_proposals", None)
    if store is None:
        store = InMemoryPendingProposalStore()
        try:
            app_state.write_planned_proposals = store
        except Exception:  # noqa: BLE001 — a read-only fake state object is not a failure
            pass
    return store


def write_planned_grant_store(app_state: Any) -> WritePlannedGrantStore:
    """The app's grant store, creating a process-local one if nothing was wired."""
    store = getattr(app_state, "write_planned_grants", None)
    if store is None:
        store = InMemoryWritePlannedGrantStore()
        try:
            app_state.write_planned_grants = store
        except Exception:  # noqa: BLE001 — a read-only fake state object is not a failure
            pass
    return store
