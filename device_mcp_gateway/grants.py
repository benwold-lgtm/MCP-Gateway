# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Elevated grants: raising a provider issuer's scope ceiling for one request (ADR-0013 §11).

§5a caps the provider plane below ``tools:call`` and every ``backup:*`` scope, which is the
carve-out that makes provider access *everyday debugging* rather than standing authority
over a customer's hardware and credentials. The ceiling that makes the carve-out real also
blocks the two elevated grants, so something has to lift it — and §11 chose a **verifiable
claim on the token, checked here**, over a second issuer entry configured with a higher
ceiling in an IdP admin console.

The whole reason that choice is worth its cost is that the bound becomes testable *in this
codebase*. Everything below is that bound, and ``tests/test_elevated_grants.py`` is it
being collected.

**What the gateway does and does not learn.** It learns that a verifiable grant may raise
an issuer's ceiling to a named set of *gateway* scopes. It never learns the provider scope
vocabulary: ``provider:invoke`` and ``provider:credentials`` are BFF scopes, they never
appear in ``ROLE_SCOPES``, and a claim naming one is simply an unknown string here. What
maps §8's two grant classes onto this module is :data:`DEFAULT_GRANT_POLICIES`, keyed on
gateway scopes — ``tools:call`` is the invoke class, ``backup:*`` the credentials class.

**Three constraints, all gateway-side, from §11b** — without them Option A quietly becomes
the option §11 rejected:

1. **The lifetime is computed against this gateway's clock, never read from the claim.**
   The BFF *requests* the grant, so an IdP hook that echoes a requested ``exp`` would let a
   compromised BFF mint itself a thirty-day credentials grant. The claim's expiry may only
   *shorten* the window (:func:`verify_grant` caps it).
2. **The authentication context is verified in the issued token, not assumed from the
   request.** ``acr_values`` is a request parameter and an IdP may decline it and issue
   anyway. The resulting ``acr`` is checked, and ``auth_time`` freshness with it, so a
   session that stepped up hours ago does not satisfy a step-up now.
3. **Revocation is bounded, not solved.** Single-use consumption closes the credentials
   class after one use; the invoke class has no revocation path inside its window. Named in
   the ADR as an accepted residual rather than left as a gap.

And from §11a: the claim names **exactly one tenant** (single-use is consumed in the
receiving tenant's own Redis, and there is deliberately no cross-stack state, so an
estate-wide grant would be independently spendable once *per gateway*), and consumption
**fails closed** — including refusing elevated grants outright in embedded mode, which has
no shared store to consume against.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, Sequence

from loguru import logger

from device_mcp_gateway.rbac import (
    SCOPE_BACKUP_EXPORT_PORTABLE,
    SCOPE_BACKUP_READ,
    SCOPE_BACKUP_WRITE,
    SCOPE_TOOLS_CALL,
)
from device_mcp_gateway.shared.keys import KEYS

#: Default name of the custom claim carrying the grant. Per-issuer config, because an IdP's
#: custom-claims hook is often constrained to a namespaced name (``https://…/grant``).
GRANT_CLAIM_DEFAULT = "mcp_grant"
#: The claim carrying the operator's tenant entitlement — the estate they may act on at all
#: (ADR-0013 §11c). Distinct from the grant claim on purpose: the grant claim is *selected*
#: by the request and so is not trusted alone, whereas this one is derived by the IdP from
#: the directory and cannot be influenced by the client.
ENTITLEMENT_CLAIM_DEFAULT = "mcp_allowed_tenants"


@dataclass(frozen=True)
class GrantPolicy:
    """The §8 window for one grant class. Durations are configuration; the *relationships*
    (credentials is single-use and no longer-lived than invoke) are the decision."""

    max_lifetime: int
    single_use: bool


#: Gateway scopes a grant may raise a ceiling to, and the §8 class each belongs to.
#:
#: ``tools:call`` is the ``provider:invoke`` class: a short **absolute** window, not one
#: call, because §8's grant gates *initiation* — an operator debugging a device makes
#: several calls inside one window.
#:
#: The ``backup:*`` scopes are the ``provider:credentials`` class: **single use**. For the
#: provider, who holds ``MCP_SECRET_KEY``, a ciphertext archive is a credential dump too
#: (§5b), so ADR-0011's ciphertext/portable distinction carries none of its weight here and
#: all three are treated alike. §8 gives this class no window at all — single use is the
#: bound — but a bound of *some* kind is still needed, or a grant minted last year is
#: spendable today. The window below is that backstop, and is deliberately no looser than
#: the invoke one.
DEFAULT_GRANT_POLICIES: Mapping[str, GrantPolicy] = {
    SCOPE_TOOLS_CALL: GrantPolicy(max_lifetime=900, single_use=False),
    SCOPE_BACKUP_READ: GrantPolicy(max_lifetime=300, single_use=True),
    SCOPE_BACKUP_WRITE: GrantPolicy(max_lifetime=300, single_use=True),
    SCOPE_BACKUP_EXPORT_PORTABLE: GrantPolicy(max_lifetime=300, single_use=True),
}

#: The closed range a grant claim may name. Equal to ``ALL_SCOPES - <provider ceiling>`` by
#: construction — a test asserts that, because the two are defined in different modules and
#: a new scope added without deciding which side of §5a it falls on would otherwise pass
#: unnoticed. A claim naming anything else is refused rather than trimmed: a grant that
#: silently grants less than it says is worse than one that fails.
GRANTABLE_SCOPES: frozenset[str] = frozenset(DEFAULT_GRANT_POLICIES)


class GrantError(Exception):
    """A grant claim was present but could not be honoured.

    The caller turns this into a **rejection of the whole token**, not a quiet fall-back to
    the unelevated principal. A caller presenting a grant is asking to act elevated; serving
    them the base principal instead means the next thing they hit is a 403 on a route, which
    reads as a permissions bug rather than a refused grant — and an expired credentials
    grant would be indistinguishable from a typo in a role mapping.
    """


@dataclass(frozen=True)
class ElevatedGrant:
    """A verified grant. ``expires_at`` is this gateway's own deadline, not the claim's."""

    id: str
    tenant: str
    scopes: frozenset[str]
    expires_at: float
    single_use: bool


class GrantConsumptionStore(Protocol):
    """Records that a single-use grant has been spent.

    ``consume`` returns True if this call claimed the id, False if it was already spent, and
    **raises** if it could not tell — the caller refuses the grant in both of the latter
    cases. A store that returned True on error would degrade single-use to
    replayable-until-expiry precisely when the backing store is unhealthy, inverting
    ADR-0006 at the moment it matters most.
    """

    async def consume(self, grant_id: str, *, ttl: int) -> bool: ...  # pragma: no cover - protocol


class MemoryGrantStore:
    """In-process consumption record. **Tests and single-replica use only.**

    Not wired into the distributed path: two gateway replicas each holding their own dict
    would let a single-use grant be spent once per replica, which is the estate-wide-grant
    failure in miniature. :class:`RedisGrantStore` is what production gets.
    """

    def __init__(self) -> None:
        self._spent: dict[str, float] = {}

    async def consume(self, grant_id: str, *, ttl: int) -> bool:
        now = time.time()
        for gid in [g for g, exp in self._spent.items() if exp <= now]:
            del self._spent[gid]
        if grant_id in self._spent:
            return False
        self._spent[grant_id] = now + ttl
        return True


class RedisGrantStore:
    """Consumption records in the receiving tenant's own Redis (§11a).

    ``SET key value NX EX ttl`` is the whole mechanism: atomic claim-or-fail in one command,
    so two concurrent replays of the same credentials grant cannot both win. The record
    expires with the grant — keeping it longer would accumulate keys for nothing, since a
    grant past its deadline is refused by the clock check before consumption is reached.
    """

    def __init__(self, redis: Any, keys: Any = KEYS) -> None:
        self._redis = redis
        self._keys = keys

    async def consume(self, grant_id: str, *, ttl: int) -> bool:
        # Any exception propagates: the caller must not be able to mistake "could not
        # write the record" for "the grant was unused".
        claimed = await self._redis.set(self._keys.grant_consumed(grant_id), "1", nx=True, ex=ttl)
        return bool(claimed)


def _policy_for(scopes: frozenset[str]) -> GrantPolicy:
    """The strictest policy across everything the grant names.

    Composition is fail-safe rather than first-wins: a claim naming both classes is
    single-use and takes the shorter window. The alternative is that adding ``tools:call``
    to a credentials grant *relaxes* it, which is a widening dressed as a detail.
    """
    policies = [DEFAULT_GRANT_POLICIES[s] for s in scopes]
    return GrantPolicy(
        max_lifetime=min(p.max_lifetime for p in policies),
        single_use=any(p.single_use for p in policies),
    )


def _parse_scopes(raw: Any) -> frozenset[str]:
    if isinstance(raw, str):  # a single scope as a bare string, as with `groups`
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        raise GrantError("grant claim has no usable 'scopes' list")
    scopes = set()
    for entry in raw:
        if not isinstance(entry, str):
            raise GrantError(f"grant claim 'scopes' contains a non-string entry: {entry!r}")
        if entry not in GRANTABLE_SCOPES:
            # Deliberately loud, and deliberately naming the offender. Three quite different
            # mistakes land here and the message has to separate them: a BFF scope
            # (`provider:invoke`) that was never a gateway scope; a scope already inside the
            # provider ceiling (`devices:read`), which needs no grant and whose presence
            # means the minting side misunderstands the model; and a typo.
            raise GrantError(
                f"grant claim names {entry!r}, which is not a grantable scope. A grant may only "
                f"raise the ceiling to {sorted(GRANTABLE_SCOPES)} (ADR-0013 §5a) — scopes already "
                f"inside the provider ceiling need no grant, and provider:* are BFF scopes the "
                f"gateway does not know."
            )
        scopes.add(entry)
    return frozenset(scopes)


def _parse_tenant(raw: Any, tenant_id: str) -> str:
    # A list is how an estate-wide grant would naturally be expressed, so it is refused by
    # type before it is compared: single-use is consumed per-gateway, which makes an
    # estate-wide grant spendable once per stack rather than once (§11a).
    if not isinstance(raw, str) or not raw:
        raise GrantError("grant claim must name exactly one tenant in a string 'tenant' field")
    if raw != tenant_id:
        # No wildcard, no "all" — the comparison is equality and nothing else, so a
        # convenience branch for estate-wide grants cannot appear without deleting a test.
        raise GrantError(f"grant claim names tenant {raw!r}, but this gateway is tenant {tenant_id!r}")
    return raw


def _check_entitlement(raw: Any, tenant: str, claim_name: str) -> None:
    """ADR-0013 §11c: the request *selected* this tenant; only the IdP can *authorize* it.

    The grant claim's ``tenant`` is chosen by whoever built the authorization request — in
    practice the BFF, which is inside the threat model. Measured against real IdPs, a
    requested scope is granted to anyone who asks for it: an operator with no entitlement to
    a tenant requested that tenant's scope and received the claim. So the tenant name alone
    asserts nothing, and this is the check that makes it mean something.

    The entitlement claim is the other half: derived by the IdP from the directory, not from
    the request, so a client cannot influence it. Both arrive in the access token, which is
    why the intersection belongs here rather than in the BFF — a check on the side that
    chose the value would be the attacker validating their own request.

    Fail-closed in every direction: a missing, malformed or empty claim refuses, because
    "no entitlement stated" and "entitled to everything" must never be the same thing.
    """
    if isinstance(raw, str):
        allowed = [raw] if raw else []
    elif isinstance(raw, list):
        allowed = [t for t in raw if isinstance(t, str) and t]
    else:
        # A claim of the wrong type is the one case that cannot be phrased as "not
        # entitled": the gateway has no idea what the IdP meant, so it says so.
        raise GrantError(
            f"token has no usable {claim_name!r} claim (got {type(raw).__name__}), so this "
            f"gateway cannot tell whether the operator may act on {tenant!r} at all; an "
            f"elevated grant needs the IdP to say so, not the request (ADR-0013 §11c)"
        )

    # **One membership test carries the whole property.** Everything above only decides
    # which sentence explains a refusal — an empty list, a blank string and a list of
    # non-strings all fail here anyway, which mutation testing confirmed by leaving those
    # branches removable without changing a single outcome. Keeping the emptiness case as
    # a separate `if` looked like defence in depth and was really an untested no-op, so it
    # is folded into the message instead of standing as its own guard.
    if tenant not in allowed:
        if not allowed:
            raise GrantError(
                f"token's {claim_name!r} claim names no tenant, so the operator is entitled "
                f"to none; an absent entitlement is not an unlimited one (ADR-0013 §11c)"
            )
        raise GrantError(
            f"grant names tenant {tenant!r}, which is not among the operator's entitled "
            f"tenants in {claim_name!r}; the request may select a tenant but only the IdP "
            f"authorizes one (ADR-0013 §11c)"
        )


async def verify_grant(
    raw: Any,
    *,
    tenant_id: Optional[str],
    step_up_acr: Sequence[str],
    acr: Any,
    auth_time: Any,
    store: Optional[GrantConsumptionStore],
    entitlement: Any = None,
    entitlement_claim: str = ENTITLEMENT_CLAIM_DEFAULT,
    leeway: int = 60,
    now: Optional[float] = None,
) -> ElevatedGrant:
    """Verify one grant claim, or raise :class:`GrantError`.

    Ordering is load-bearing. Consumption happens **last**, after every other check has
    passed, so a grant refused for an unrelated reason — clock skew, a wrong ``acr`` — does
    not burn its id and leave a legitimate single-use grant unspendable for good.
    """
    now = time.time() if now is None else now

    # --- preconditions the operator owns. All fail closed. ---------------------
    if not tenant_id:
        # A gateway that does not know its own name cannot check that a grant names *it*,
        # so it must honour none. Guarded again at startup for provider issuers, since
        # discovering this during an incident is the worst possible moment.
        raise GrantError("this gateway has no configured tenant_id, so it cannot honour an elevated grant")
    if not step_up_acr:
        raise GrantError(
            "no step_up_acr is configured for this issuer, so the step-up behind an elevated grant "
            "cannot be verified (ADR-0013 §11b)"
        )
    if store is None:
        # Embedded mode, or a startup that has not attached the store yet. §11a refuses *an
        # elevated grant* without a shared store — not merely the single-use ones — because
        # without one the gateway cannot enforce the property that made a checked claim
        # preferable to a configured issuer in the first place.
        raise GrantError(
            "no grant consumption store is available (embedded mode has no shared store), so an "
            "elevated grant cannot be honoured (ADR-0013 §11a)"
        )

    # --- the claim itself ------------------------------------------------------
    if not isinstance(raw, dict):
        raise GrantError(f"grant claim must be an object, got {type(raw).__name__}")
    grant_id = raw.get("id")
    if not isinstance(grant_id, str) or not grant_id:
        raise GrantError("grant claim has no usable 'id' — nothing to consume against, and nothing to audit")
    tenant = _parse_tenant(raw.get("tenant"), tenant_id)
    # §11c, and it must sit here: after the tenant is known to be well-formed and to name
    # this gateway, and well before consumption, so an operator who is simply not entitled
    # to this tenant does not burn a legitimate single-use grant id on the way to a refusal.
    if not entitlement_claim:
        raise GrantError(
            "no entitlement_claim is configured for this issuer, so the operator's entitlement "
            "to the named tenant cannot be checked; the request would be selecting a tenant "
            "with nothing authorizing it (ADR-0013 §11c)"
        )
    _check_entitlement(entitlement, tenant, entitlement_claim)
    scopes = _parse_scopes(raw.get("scopes"))
    policy = _policy_for(scopes)

    # --- constraint 2: the step-up happened, and happened recently -------------
    if not isinstance(acr, str) or acr not in step_up_acr:
        # A missing `acr` lands here too, and must: `acr_values` is a *request* parameter
        # and an IdP may decline the step-up and issue anyway. Requesting is not achieving.
        raise GrantError(
            f"token acr {acr!r} is not one of the configured step-up contexts {list(step_up_acr)}; "
            f"an elevated grant requires a step-up in the issued token, not a requested one"
        )
    if not isinstance(auth_time, (int, float)) or isinstance(auth_time, bool):
        raise GrantError("token has no usable auth_time, so the step-up cannot be dated")
    if auth_time > now + leeway:
        # Otherwise the freshness check is defeated from the same place it is enforced.
        raise GrantError("token auth_time is in the future")

    # --- constraint 1: the deadline is ours, and the claim may only shorten it --
    deadline = float(auth_time) + policy.max_lifetime
    claim_exp = raw.get("exp")
    if isinstance(claim_exp, (int, float)) and not isinstance(claim_exp, bool):
        if claim_exp < deadline:
            deadline = float(claim_exp)
        else:
            logger.warning(
                f"grant {grant_id!r} carries exp={claim_exp} beyond the {policy.max_lifetime}s policy "
                f"window for {sorted(scopes)}; capping to the gateway-computed deadline. A hook echoing "
                f"a requested expiry is how ADR-0013 §8's windows become suggestions."
            )
    # ``leeway`` is clock-skew tolerance, not slack in the window: ``auth_time`` and any
    # claim ``exp`` are stamped by the IdP's clock, and this is the same tolerance already
    # applied to the token's own ``exp``. It is bounded and configurable, so a deployment
    # that wants none sets ``leeway: 0`` and gets none.
    if deadline <= now - leeway:
        # One message for both causes — a stale step-up and an expired claim are the same
        # condition once the deadline is computed, and splitting them would invite an
        # implementation where only one of the two is actually checked.
        raise GrantError(
            f"grant {grant_id!r} expired: its window closed at {deadline:.0f} (auth_time "
            f"{float(auth_time):.0f} + {policy.max_lifetime}s, capped by any claim exp)"
        )

    # --- §11a: consumption, last and fail-closed --------------------------------
    if policy.single_use:
        ttl = max(int(deadline - now) + leeway, leeway)
        try:
            claimed = await store.consume(grant_id, ttl=ttl)
        except Exception as exc:
            raise GrantError(f"could not record consumption of single-use grant {grant_id!r}, refusing it: {exc}")
        if not claimed:
            raise GrantError(f"single-use grant {grant_id!r} has already been spent")

    return ElevatedGrant(
        id=grant_id,
        tenant=tenant,
        scopes=scopes,
        expires_at=deadline,
        single_use=policy.single_use,
    )
