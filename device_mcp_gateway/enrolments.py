# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Enrolment: the standing relationship between this tenant and its provider (ADR-0024 §10).

Connecting a tenant to its provider was nine manual steps across two clusters and an identity
provider, three of them failing silently. §10 replaces them with one act: **the tenant issues an
invitation, the provider redeems it once, and redemption creates every piece of state the
connection needs on both sides.**

Two objects, and the difference between them is the whole design:

* An **invitation** is a one-time, short-lived code the tenant generates in its own console and
  hands over out of band. It exists to solve a bootstrap problem — a provider cannot raise a
  request against a tenant's gateway before it holds a credential to raise one with — without
  opening an unauthenticated endpoint, which §10 rejects for the reason ADR-0017 §7a rejected
  an unauthenticated raise route: that trade belongs to the tenant, not to a default.

* An **enrolment** is what redemption produces, and it **does not expire**. ADR-0017's grants
  are time-boxed because a grant carries capability. An enrolment carries none: the provider's
  side of it permits one verb, *ask*. An expiry here would not be a security control but "a
  scheduled outage with a security-shaped name" — on a timer nobody watches, the provider
  silently loses the ability to be asked for help, and the first symptom is a support request
  that cannot be raised during the incident that prompted it.

**What replaces expiry, because something must.** An expiry's one virtue is forcing periodic
re-examination. That requirement transfers rather than disappearing: every enrolment is listed
in the tenant's own console with who approved it and when, and carries `last_used_at` sourced
from real requests rather than self-reported — so a dormant supplier relationship is
discoverable by looking rather than by remembering. Revocation is immediate and needs no
counterparty.

**Credentials are stored hashed, never verbatim.** Both the invitation code and the enrolment
credential are bearer secrets; keeping them in Redis in the clear would put live credentials in
the keyspace, which is what ADR-0018's by-reference discipline exists to avoid. Redemption and
authentication hash what they are given and look that up, so this store can recognise a
credential it could not present.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal, Optional, Protocol

from loguru import logger

from device_mcp_gateway.shared.keys import KEYS

#: Prefix on the credential a redeemed enrolment mints. Serves the same purpose as
#: `support_grants.SUPPORT_GRANT_TOKEN_PREFIX`: a cheap shape check, so a bearer of any other
#: form never pays for a store round-trip on the authentication fall-through path.
ENROLMENT_TOKEN_PREFIX = "enr_"

#: Prefix on an invitation code. Distinct from the above because the two are presented to
#: different routes and mean different things — a code that authenticates a redemption is not a
#: credential that authenticates a request, and a mechanism that could confuse them would let a
#: one-time bootstrap secret stand in for a standing one.
INVITATION_CODE_PREFIX = "inv_"

#: Default invitation lifetime. Short on purpose: it is handed over out of band, and the window
#: in which a copy is useful should be the window in which the handover is actually happening.
DEFAULT_INVITATION_TTL_SECONDS = 3600

RedeemReason = Literal["not_found", "expired", "already_redeemed"]
EnrolmentCheckReason = Literal["not_found", "revoked"]


def is_enrolment_token(token: str) -> bool:
    return token.startswith(ENROLMENT_TOKEN_PREFIX)


def hash_credential(value: str) -> str:
    """The stored form of a bearer secret.

    Plain SHA-256, deliberately not a password KDF: these are full-entropy machine-generated
    secrets (`secrets.token_urlsafe(32)`), not user-chosen passwords, so there is no dictionary
    to slow an attacker down against. A KDF here would buy nothing and cost a lookup on the hot
    authentication path — the same reasoning the gateway already applies to API-key comparison.
    """
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class Invitation:
    """An unredeemed invitation. Note it carries no code — only its hash.

    The plaintext code exists exactly once, in the response that created it. If the tenant
    admin loses it, the answer is to issue another and let this one expire, not to recover it:
    a store that can re-show a credential is a store that can leak one.
    """

    code_hash: str
    created_by: str
    created_at: float
    expires_at: float
    #: What the tenant is inviting. Recorded at creation so the console can show "this
    #: invitation is for Acme" rather than an anonymous code, and so an admin approving the
    #: handover knows who they are expecting to redeem it.
    provider_label: str


@dataclass(frozen=True)
class Enrolment:
    """A live relationship. Everything the tenant console lists comes from here."""

    enrolment_id: str
    provider_subject: str
    provider_label: str
    #: The identity of the tenant admin who issued the invitation this came from — §10's "who
    #: approved it and when", which is the visibility that replaces expiry.
    approved_by: str
    approved_at: float
    #: Where the provider's catalog lives, and this tenant's own credential for it, delivered
    #: by the provider at redemption. Held here rather than in config because ADR-0020 §7a's
    #: per-tenant credential has to come from somewhere, and §10 is that somewhere: "approving
    #: one is the moment a tenant first needs catalog access."
    catalog_url: str
    #: **Encrypted, not hashed** — the one credential in this module that must be readable
    #: again. The invitation code and the enrolment credential are only ever *recognised*, so
    #: a one-way hash is exactly right for them. This one has to be *used*: the tenant's own
    #: console presents it to the catalog on every request (ADR-0020 §7b's declaration flow),
    #: so a store that could not return it would produce an enrolment that looks complete and
    #: leaves the catalog silently unreachable — step 9 of §10's nine, which is the failure
    #: this whole mechanism exists to remove.
    #:
    #: Encrypted under the gateway's existing `CredentialCodec` (`app.state.codec`), the same
    #: mechanism device credentials use, rather than a second scheme. With no `MCP_SECRET_KEY`
    #: the codec is a no-op and this is plaintext at rest — the pre-existing, documented
    #: trade-off for that configuration, not a new one introduced here.
    catalog_credential_encrypted: str
    #: Sourced from real authenticated requests, never self-reported (§10). `None` means the
    #: provider has not used it since it was approved — which is exactly the dormancy signal
    #: the listing exists to make visible.
    last_used_at: Optional[float] = None
    revoked_at: Optional[float] = None

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None


@dataclass(frozen=True)
class RedeemResult:
    ok: bool
    reason: Optional[RedeemReason] = None
    enrolment: Optional[Enrolment] = None
    #: The minted credential, plaintext, returned exactly once — to the provider redeeming.
    credential: Optional[str] = None


@dataclass(frozen=True)
class EnrolmentCheckResult:
    ok: bool
    reason: Optional[EnrolmentCheckReason] = None
    enrolment: Optional[Enrolment] = None


class InvitationStore(Protocol):
    async def create(self, *, created_by: str, provider_label: str, ttl_seconds: int) -> tuple[str, Invitation]:
        """Mint an invitation, returning `(plaintext_code, invitation)`.

        The code is returned and never stored; see `Invitation`.
        """
        ...

    async def list_live(self) -> list[Invitation]: ...

    async def revoke(self, code_hash: str) -> bool:
        """Withdraw an unredeemed invitation. A handover that went wrong should be endable
        before it is redeemed, not only after."""
        ...


class EnrolmentStore(Protocol):
    async def redeem(
        self, *, code: str, provider_subject: str, catalog_url: str, catalog_credential: str
    ) -> RedeemResult:
        """Consume an invitation and create the enrolment it authorises.

        **Single-use is enforced here, atomically**, not by the caller checking first and
        deleting after: two providers racing the same code must produce one enrolment and one
        refusal, and a check-then-act would produce two. The same reasoning
        `write_planned.check_and_consume` already applies to its own single-use grant.
        """
        ...

    async def check(self, credential: str) -> EnrolmentCheckResult:
        """Resolve a presented credential to its enrolment, live-checked.

        Called on **every** request the provider makes, deliberately — the same posture
        ADR-0017 §8 requires of support grants, and for a stronger reason here: with no expiry,
        revocation is the only control, so it has to take effect on the next request rather
        than at the next refresh of something cached.
        """
        ...

    async def note_used(self, enrolment_id: str, *, when: Optional[float] = None) -> None:
        """Record that the enrolment was used. Best-effort and never on the request's critical
        path: `last_used_at` exists to make dormancy visible, and failing a provider's request
        because a usage timestamp could not be written would be a worse outcome than a stale
        timestamp."""
        ...

    async def list_all(self, *, include_revoked: bool = False) -> list[Enrolment]: ...

    async def get(self, enrolment_id: str) -> Optional[Enrolment]: ...

    async def revoke(self, enrolment_id: str) -> EnrolmentCheckResult:
        """End the relationship. Idempotent: revoking an already-revoked enrolment reports the
        same outcome rather than an error, because a tenant admin clicking twice during an
        incident must not see a failure."""
        ...


class _NullCodec:
    """Used when no codec is supplied — keeps the store constructible in tests and in an
    embedded stack with no secret key, matching `CredentialCodec`'s own disabled behaviour
    rather than inventing a second "encryption is off" convention."""

    def encrypt(self, plaintext: str) -> str:
        return plaintext

    def decrypt(self, stored: str) -> str:
        return stored


def _new_invitation_code() -> str:
    return INVITATION_CODE_PREFIX + secrets.token_urlsafe(32)


def _new_enrolment_credential() -> str:
    return ENROLMENT_TOKEN_PREFIX + secrets.token_urlsafe(32)


class InMemoryInvitationStore:
    """Embedded-mode invitation store. Single process, so a dict is the whole implementation."""

    def __init__(self) -> None:
        self._invitations: dict[str, dict[str, Any]] = {}

    async def create(self, *, created_by: str, provider_label: str, ttl_seconds: int) -> tuple[str, Invitation]:
        code = _new_invitation_code()
        now = time.time()
        inv = Invitation(
            code_hash=hash_credential(code),
            created_by=created_by,
            created_at=now,
            expires_at=now + ttl_seconds,
            provider_label=provider_label,
        )
        self._invitations[inv.code_hash] = {"invitation": inv, "redeemed": False}
        return code, inv

    def _live(self, code_hash: str) -> Optional[dict[str, Any]]:
        row = self._invitations.get(code_hash)
        if row is None:
            return None
        if row["invitation"].expires_at <= time.time():
            # Expiry is enforced on read rather than by a sweeper. The Redis store gets this
            # from a TTL; here there is no reaper, so an expired row must not be usable even
            # though it is still present.
            return None
        return row

    async def list_live(self) -> list[Invitation]:
        return [
            row["invitation"]
            for row in self._invitations.values()
            if self._live(row["invitation"].code_hash) and not row["redeemed"]
        ]

    async def revoke(self, code_hash: str) -> bool:
        return self._invitations.pop(code_hash, None) is not None


class InMemoryEnrolmentStore:
    def __init__(self, invitations: InMemoryInvitationStore, codec: Any = None) -> None:
        self._invitations = invitations
        self._codec = codec or _NullCodec()
        self._enrolments: dict[str, Enrolment] = {}
        self._by_credential: dict[str, str] = {}

    async def redeem(
        self, *, code: str, provider_subject: str, catalog_url: str, catalog_credential: str
    ) -> RedeemResult:
        code_hash = hash_credential(code)
        row = self._invitations._invitations.get(code_hash)
        if row is None:
            return RedeemResult(ok=False, reason="not_found")
        if row["redeemed"]:
            return RedeemResult(ok=False, reason="already_redeemed")
        if row["invitation"].expires_at <= time.time():
            return RedeemResult(ok=False, reason="expired")
        # Single-threaded event loop with no await between the check and the flag, so this is
        # atomic here for the same reason the Redis store needs an explicit primitive to be.
        row["redeemed"] = True

        inv: Invitation = row["invitation"]
        credential = _new_enrolment_credential()
        enrolment = Enrolment(
            enrolment_id=secrets.token_urlsafe(16),
            provider_subject=provider_subject,
            provider_label=inv.provider_label,
            approved_by=inv.created_by,
            approved_at=time.time(),
            catalog_url=catalog_url,
            catalog_credential_encrypted=self._codec.encrypt(catalog_credential),
        )
        self._enrolments[enrolment.enrolment_id] = enrolment
        self._by_credential[hash_credential(credential)] = enrolment.enrolment_id
        return RedeemResult(ok=True, enrolment=enrolment, credential=credential)

    async def check(self, credential: str) -> EnrolmentCheckResult:
        enrolment_id = self._by_credential.get(hash_credential(credential))
        if enrolment_id is None:
            return EnrolmentCheckResult(ok=False, reason="not_found")
        enrolment = self._enrolments.get(enrolment_id)
        if enrolment is None:
            return EnrolmentCheckResult(ok=False, reason="not_found")
        if not enrolment.is_live:
            return EnrolmentCheckResult(ok=False, reason="revoked", enrolment=enrolment)
        return EnrolmentCheckResult(ok=True, enrolment=enrolment)

    async def note_used(self, enrolment_id: str, *, when: Optional[float] = None) -> None:
        existing = self._enrolments.get(enrolment_id)
        if existing is None:
            return
        from dataclasses import replace

        self._enrolments[enrolment_id] = replace(existing, last_used_at=when or time.time())

    async def list_all(self, *, include_revoked: bool = False) -> list[Enrolment]:
        rows = list(self._enrolments.values())
        if not include_revoked:
            rows = [e for e in rows if e.is_live]
        return sorted(rows, key=lambda e: e.approved_at)

    async def get(self, enrolment_id: str) -> Optional[Enrolment]:
        return self._enrolments.get(enrolment_id)

    async def revoke(self, enrolment_id: str) -> EnrolmentCheckResult:
        existing = self._enrolments.get(enrolment_id)
        if existing is None:
            return EnrolmentCheckResult(ok=False, reason="not_found")
        if not existing.is_live:
            # Idempotent: report the same shape as a fresh revoke rather than an error.
            return EnrolmentCheckResult(ok=True, enrolment=existing)
        from dataclasses import replace

        revoked = replace(existing, revoked_at=time.time())
        self._enrolments[enrolment_id] = revoked
        return EnrolmentCheckResult(ok=True, enrolment=revoked)


class RedisInvitationStore:
    """Invitations shared across gateway replicas.

    Falls back to process-local state on any Redis error, the same trade
    `RedisPendingSupportRequestStore` already makes: an invitation that vanished mid-handover
    because of a Redis blip would strand an enrolment a human was in the middle of performing.
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client
        self._fallback = InMemoryInvitationStore()

    async def create(self, *, created_by: str, provider_label: str, ttl_seconds: int) -> tuple[str, Invitation]:
        code = _new_invitation_code()
        now = time.time()
        inv = Invitation(
            code_hash=hash_credential(code),
            created_by=created_by,
            created_at=now,
            expires_at=now + ttl_seconds,
            provider_label=provider_label,
        )
        try:
            key = KEYS.enrolment_invitation(inv.code_hash)
            pipe = self._r.pipeline(transaction=True)
            pipe.hset(
                key,
                mapping={
                    "created_by": created_by,
                    "provider_label": provider_label,
                    "created_at": str(now),
                    "expires_at": str(inv.expires_at),
                    "redeemed": "",
                },
            )
            # The TTL is the expiry. Unlike the enrolment this produces, an invitation is the
            # part that is supposed to lapse, so Redis reaping it IS the enforcement rather
            # than a cleanup detail — and `_live` still checks `expires_at` for the window
            # between logical expiry and the key actually going away.
            pipe.expire(key, ttl_seconds)
            pipe.sadd(KEYS.enrolment_invitation_index, inv.code_hash)
            await pipe.execute()
            return code, inv
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"invitation store fell back to process-local state: {exc}")
            return await self._fallback.create(
                created_by=created_by, provider_label=provider_label, ttl_seconds=ttl_seconds
            )

    async def list_live(self) -> list[Invitation]:
        try:
            members = await self._r.smembers(KEYS.enrolment_invitation_index)
            out: list[Invitation] = []
            stale: list[str] = []
            for raw in members:
                code_hash = raw.decode() if isinstance(raw, bytes) else str(raw)
                row = await self._r.hgetall(KEYS.enrolment_invitation(code_hash))
                if not row:
                    # The hash's TTL reaped it independently of this index — expected, not an
                    # error. Same best-effort membership contract as `support_pending_index`.
                    stale.append(code_hash)
                    continue
                fields = {
                    (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                    for k, v in row.items()
                }
                if fields.get("redeemed"):
                    continue
                out.append(
                    Invitation(
                        code_hash=code_hash,
                        created_by=fields.get("created_by", ""),
                        created_at=float(fields.get("created_at", 0.0)),
                        expires_at=float(fields.get("expires_at", 0.0)),
                        provider_label=fields.get("provider_label", ""),
                    )
                )
            if stale:
                await self._r.srem(KEYS.enrolment_invitation_index, *stale)
            return sorted(out, key=lambda i: i.created_at)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"invitation listing fell back to process-local state: {exc}")
            return await self._fallback.list_live()

    async def revoke(self, code_hash: str) -> bool:
        try:
            pipe = self._r.pipeline(transaction=True)
            pipe.delete(KEYS.enrolment_invitation(code_hash))
            pipe.srem(KEYS.enrolment_invitation_index, code_hash)
            deleted, _ = await pipe.execute()
            return bool(deleted)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"invitation revoke fell back to process-local state: {exc}")
            return await self._fallback.revoke(code_hash)


class RedisEnrolmentStore:
    """Enrolments shared across gateway replicas.

    **No fallback on `check`.** Every other store in this module degrades to process-local
    state when Redis is unavailable, because losing an in-flight human workflow is worse than
    running degraded. `check` is different: it is the authentication path, and a fallback there
    would admit a credential this replica cannot confirm is still live — turning a Redis outage
    into a window where revocation silently stops working. With no expiry on an enrolment,
    revocation is the ONLY control, so it fails closed instead.
    """

    def __init__(self, redis_client: Any, invitations: RedisInvitationStore, codec: Any = None) -> None:
        self._r = redis_client
        self._invitations = invitations
        self._codec = codec or _NullCodec()

    async def redeem(
        self, *, code: str, provider_subject: str, catalog_url: str, catalog_credential: str
    ) -> RedeemResult:
        code_hash = hash_credential(code)
        key = KEYS.enrolment_invitation(code_hash)
        row = await self._r.hgetall(key)
        if not row:
            return RedeemResult(ok=False, reason="not_found")
        fields = {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in row.items()
        }
        if float(fields.get("expires_at", 0.0)) <= time.time():
            return RedeemResult(ok=False, reason="expired")

        # Atomic single-use. `hset(..., nx=True)` succeeds for exactly one caller, so two
        # providers racing the same code produce one enrolment and one refusal — a
        # check-then-write would produce two. The same primitive `mark_approved` uses to make
        # a decision deliverable exactly once.
        won = await self._r.hsetnx(key, "redeemed", str(time.time()))
        if not won:
            return RedeemResult(ok=False, reason="already_redeemed")

        credential = _new_enrolment_credential()
        enrolment = Enrolment(
            enrolment_id=secrets.token_urlsafe(16),
            provider_subject=provider_subject,
            provider_label=fields.get("provider_label", ""),
            approved_by=fields.get("created_by", ""),
            approved_at=time.time(),
            catalog_url=catalog_url,
            catalog_credential_encrypted=self._codec.encrypt(catalog_credential),
        )
        pipe = self._r.pipeline(transaction=True)
        pipe.hset(
            KEYS.enrolment(enrolment.enrolment_id),
            mapping={
                "provider_subject": enrolment.provider_subject,
                "provider_label": enrolment.provider_label,
                "approved_by": enrolment.approved_by,
                "approved_at": str(enrolment.approved_at),
                "catalog_url": enrolment.catalog_url,
                "catalog_credential_encrypted": enrolment.catalog_credential_encrypted,
                # The enrolment credential's OWN hash, kept so `revoke` can delete the
                # credential->id mapping it created. Deliberately not a field on `Enrolment`:
                # that object is serialised to the tenant console, and a credential hash is
                # not something a listing needs to carry around to be useful.
                "credential_hash": hash_credential(credential),
                "last_used_at": "",
                "revoked_at": "",
            },
        )
        # Deliberately NO `expire` on either key. See `KEYS.enrolment` and §10.
        pipe.sadd(KEYS.enrolment_index, enrolment.enrolment_id)
        pipe.set(KEYS.enrolment_credential(hash_credential(credential)), enrolment.enrolment_id)
        pipe.srem(KEYS.enrolment_invitation_index, code_hash)
        await pipe.execute()
        return RedeemResult(ok=True, enrolment=enrolment, credential=credential)

    def _to_enrolment(self, enrolment_id: str, fields: dict[str, str]) -> Enrolment:
        return Enrolment(
            enrolment_id=enrolment_id,
            provider_subject=fields.get("provider_subject", ""),
            provider_label=fields.get("provider_label", ""),
            approved_by=fields.get("approved_by", ""),
            approved_at=float(fields.get("approved_at", 0.0)),
            catalog_url=fields.get("catalog_url", ""),
            catalog_credential_encrypted=fields.get("catalog_credential_encrypted", ""),
            last_used_at=float(fields["last_used_at"]) if fields.get("last_used_at") else None,
            revoked_at=float(fields["revoked_at"]) if fields.get("revoked_at") else None,
        )

    async def _fields(self, enrolment_id: str) -> Optional[dict[str, str]]:
        row = await self._r.hgetall(KEYS.enrolment(enrolment_id))
        if not row:
            return None
        return {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in row.items()
        }

    async def check(self, credential: str) -> EnrolmentCheckResult:
        # No try/except fallback here on purpose — see the class docstring.
        raw = await self._r.get(KEYS.enrolment_credential(hash_credential(credential)))
        if raw is None:
            return EnrolmentCheckResult(ok=False, reason="not_found")
        enrolment_id = raw.decode() if isinstance(raw, bytes) else str(raw)
        fields = await self._fields(enrolment_id)
        if fields is None:
            return EnrolmentCheckResult(ok=False, reason="not_found")
        enrolment = self._to_enrolment(enrolment_id, fields)
        if not enrolment.is_live:
            return EnrolmentCheckResult(ok=False, reason="revoked", enrolment=enrolment)
        return EnrolmentCheckResult(ok=True, enrolment=enrolment)

    async def note_used(self, enrolment_id: str, *, when: Optional[float] = None) -> None:
        try:
            await self._r.hset(KEYS.enrolment(enrolment_id), "last_used_at", str(when or time.time()))
        except Exception as exc:  # noqa: BLE001 — best-effort by contract; see the Protocol.
            logger.warning(f"could not record enrolment last-used: {exc}")

    async def list_all(self, *, include_revoked: bool = False) -> list[Enrolment]:
        members = await self._r.smembers(KEYS.enrolment_index)
        out: list[Enrolment] = []
        for raw in members:
            enrolment_id = raw.decode() if isinstance(raw, bytes) else str(raw)
            fields = await self._fields(enrolment_id)
            if fields is None:
                continue
            enrolment = self._to_enrolment(enrolment_id, fields)
            if enrolment.is_live or include_revoked:
                out.append(enrolment)
        return sorted(out, key=lambda e: e.approved_at)

    async def get(self, enrolment_id: str) -> Optional[Enrolment]:
        fields = await self._fields(enrolment_id)
        return self._to_enrolment(enrolment_id, fields) if fields else None

    async def revoke(self, enrolment_id: str) -> EnrolmentCheckResult:
        fields = await self._fields(enrolment_id)
        if fields is None:
            return EnrolmentCheckResult(ok=False, reason="not_found")
        existing = self._to_enrolment(enrolment_id, fields)
        if not existing.is_live:
            return EnrolmentCheckResult(ok=True, enrolment=existing)
        now = time.time()
        pipe = self._r.pipeline(transaction=True)
        pipe.hset(KEYS.enrolment(enrolment_id), "revoked_at", str(now))
        # The credential mapping is DELETED as well as the record being marked. Either alone
        # would refuse the next request — `check` reads the record and sees `revoked_at` — so
        # this is defence in depth on the one control an enrolment has, and it makes the
        # refusal cost one lookup instead of two. Keyed by the ENROLMENT credential's hash,
        # which is why that is stored above: the catalog credential's hash is a different
        # secret entirely, and deleting by it would silently no-op.
        credential_hash = fields.get("credential_hash", "")
        if credential_hash:
            pipe.delete(KEYS.enrolment_credential(credential_hash))
        await pipe.execute()
        from dataclasses import replace

        return EnrolmentCheckResult(ok=True, enrolment=replace(existing, revoked_at=now))


def invitation_store(state: Any) -> InvitationStore:
    return state.enrolment_invitations  # type: ignore[no-any-return]


def enrolment_store(state: Any) -> EnrolmentStore:
    return state.enrolments  # type: ignore[no-any-return]


__all__ = [
    "ENROLMENT_TOKEN_PREFIX",
    "INVITATION_CODE_PREFIX",
    "DEFAULT_INVITATION_TTL_SECONDS",
    "Enrolment",
    "EnrolmentCheckResult",
    "EnrolmentStore",
    "Invitation",
    "InvitationStore",
    "InMemoryEnrolmentStore",
    "InMemoryInvitationStore",
    "RedisEnrolmentStore",
    "RedisInvitationStore",
    "RedeemResult",
    "enrolment_store",
    "hash_credential",
    "invitation_store",
    "is_enrolment_token",
    "KEYS",
]
