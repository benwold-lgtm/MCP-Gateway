# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0013 §8/§11 — an elevated grant reaching a tenant gateway as a verifiable claim.

**Written before the implementation, deliberately** — the same discipline as
``test_multi_issuer_isolation.py``, and for the same reason: every property here fails
*silently* when it regresses. The token still validates, the request still succeeds, and
the only symptom is that someone held `tools:call` or `backup:*` on a customer's stack when
they should not have. Nothing else in the suite would notice.

§11 chose a checked claim over a second issuer entry with a higher ceiling precisely
because a bound living in an IdP admin console is untestable *here*. That argument only
pays off if the checks below actually exist, so this file is the payoff being collected.

The seven hazards, each of which the obvious implementation walks straight into:

1. **The claim's expiry taken as authoritative.** The BFF *requests* the grant, so if the
   IdP hook echoes a requested ``exp`` a compromised BFF mints itself a thirty-day
   ``backup:export-portable``. §8's windows become suggestions. The gateway must compute
   the deadline against its own clock and let the claim only *shorten* it (§11b constraint 1).
2. **Requesting a step-up mistaken for achieving one.** ``acr_values`` is a request
   parameter; an IdP may decline it and issue anyway. Checking that step-up was asked for
   rather than that it happened is the same shape as reading a default as a measurement.
3. **A stale step-up.** ``auth_time`` from three hours ago satisfying an elevation now —
   which is a sliding window wearing an absolute window's clothes (§8).
4. **An estate-wide grant.** A claim naming no tenant, several tenants, or a *different*
   tenant. Single-use is consumed in the receiving tenant's own Redis and there is
   deliberately no cross-stack state (§1), so an unbound grant is independently spendable
   once **per gateway** (§11a constraint 1).
5. **Single-use degrading to replayable.** A consumption record that cannot be written —
   Redis down, or embedded mode with no shared store at all — permitting the grant instead
   of refusing it. That inverts ADR-0006 exactly when the store is unhealthy (§11a
   constraint 2).
6. **A grant honoured on a ceiling-less issuer.** The escalation arriving from the
   *tenant's own* IdP: if the union happens before the plane is consulted, any tenant
   viewer whose IdP can be made to emit the claim gains ``tools:call`` on their own stack.
   This is §6a's hazard one layer up, and the union direction makes it easy to miss.
7. **The provider scope vocabulary leaking into the gateway.** §11 keeps one line: the
   gateway learns that a verifiable grant may raise a ceiling, and never learns what
   ``provider:invoke`` is. A claim naming a BFF scope — or any string at all — must not
   reach a principal's scope set.

Real RSA keys throughout, seeded into the caches, so the whole file runs offline.
"""

from __future__ import annotations

import ast
import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from loguru import logger

import device_mcp_gateway
from device_mcp_gateway.audit import audit_request, grant_fields
from device_mcp_gateway.grants import (
    DEFAULT_GRANT_POLICIES,
    GRANTABLE_SCOPES,
    GrantError,
    MemoryGrantStore,
    RedisGrantStore,
    ENTITLEMENT_CLAIM_DEFAULT,
    verify_grant,
)
from device_mcp_gateway.oidc import (
    PLANE_PROVIDER,
    PLANE_TENANT,
    MultiIssuerValidator,
    OIDCConfig,
    OIDCError,
)
from device_mcp_gateway.rbac import (
    SCOPE_BACKUP_EXPORT_PORTABLE,
    SCOPE_BACKUP_READ,
    SCOPE_DEVICES_READ,
    SCOPE_DEVICES_WRITE,
    SCOPE_METRICS_READ,
    SCOPE_TOOLS_CALL,
    Principal,
)
from device_mcp_gateway.shared.keys import KEYS

# Nearly every test here is async; the two that are not are written async anyway so the
# module carries one marker rather than thirty.
pytestmark = pytest.mark.asyncio

TENANT_ISS = "https://tenant-idp.example.com"
PROVIDER_ISS = "https://provider-idp.example.com"
AUDIENCE = "device-mcp-gateway"
TENANT_ID = "acme"
STEP_UP_ACR = "urn:mcp:provider:step-up"
#: Issuer-qualified, exactly as ``_build_principal`` produces it — the single-use record is
#: keyed partly on this, so a test using a bare ``sub`` would not exercise the real shape.
SUBJECT = f"oidc:{PROVIDER_ISS}#opsuser"


# --- rig ----------------------------------------------------------------------


def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(priv: rsa.RSAPrivateKey, kid: str) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    return jwk


def _grant(**over) -> dict:
    """A well-formed grant claim. Tests override exactly the field under test, so a
    failure names one cause rather than "the fixture differs somewhere"."""
    claim = {"id": "grant-001", "tenant": TENANT_ID, "scopes": [SCOPE_TOOLS_CALL]}
    claim.update(over)
    return claim


def _verify(**over):
    """Call ``verify_grant`` with a valid argument set, overriding one thing.

    The defaults deliberately describe a grant that *should* succeed — several tests below
    assert exactly that, so a fixture that had drifted into failing for an unrelated reason
    would be caught rather than quietly making the negative tests vacuous.
    """
    now = over.pop("now", time.time())
    args = dict(
        raw=_grant(),
        tenant_id=TENANT_ID,
        subject=SUBJECT,
        step_up_acr=(STEP_UP_ACR,),
        acr=STEP_UP_ACR,
        auth_time=int(now) - 30,
        store=MemoryGrantStore(),
        # §11c: the IdP's own statement of which tenants this operator may act on. The
        # default entitles them to this gateway's tenant, so the checks below still fail
        # for the one reason each is testing.
        entitlement=[TENANT_ID, "some-other-tenant"],
        now=now,
    )
    args.update(over)
    return verify_grant(**args)


@pytest.fixture
def store():
    return MemoryGrantStore()


# --- the shape of the policy table --------------------------------------------


async def test_grantable_scopes_are_exactly_those_outside_the_provider_ceiling():
    """The grant exists to lift the §5a carve-out, so the grantable set and the carve-out
    must be the same set. Written as an assertion rather than a comment because the two
    are defined in different modules: adding a scope to ``ALL_SCOPES`` without deciding
    which side of §5a it falls on would otherwise pass unnoticed."""
    from device_mcp_gateway.oidc import PLANE_SCOPE_CEILING
    from device_mcp_gateway.rbac import ALL_SCOPES

    ceiling = PLANE_SCOPE_CEILING[PLANE_PROVIDER]
    assert GRANTABLE_SCOPES == ALL_SCOPES - ceiling


async def test_credentials_class_grants_are_single_use_and_invoke_is_not():
    """§8's relationships, which are the decision — the durations are configuration.
    ``backup:*`` is the ``provider:credentials`` class (single use); ``tools:call`` is the
    ``provider:invoke`` class (a short absolute window)."""
    assert DEFAULT_GRANT_POLICIES[SCOPE_TOOLS_CALL].single_use is False
    for scope in (SCOPE_BACKUP_READ, SCOPE_BACKUP_EXPORT_PORTABLE):
        assert DEFAULT_GRANT_POLICIES[scope].single_use is True
    # ...and the credentials window is no longer than the invoke one. A single-use grant
    # still needs a bound (§8 names none), and it must not be the *looser* of the two.
    assert (
        DEFAULT_GRANT_POLICIES[SCOPE_BACKUP_READ].max_lifetime <= DEFAULT_GRANT_POLICIES[SCOPE_TOOLS_CALL].max_lifetime
    )


# --- the happy path, so the negatives below are not vacuous --------------------


async def test_a_well_formed_grant_is_accepted():
    grant = await _verify()
    assert grant.id == "grant-001"
    assert grant.tenant == TENANT_ID
    assert grant.scopes == frozenset({SCOPE_TOOLS_CALL})


async def test_the_deadline_is_the_step_up_plus_the_policy_window():
    """The window runs from the step-up, not from the request: that is what makes it
    absolute. A grant used 10 minutes after step-up has 5 minutes left, not 15."""
    now = time.time()
    grant = await _verify(auth_time=int(now) - 600, now=now)
    window = DEFAULT_GRANT_POLICIES[SCOPE_TOOLS_CALL].max_lifetime
    assert grant.expires_at == pytest.approx(now - 600 + window, abs=2)


# --- Hazard 1: the claim's expiry is a ceiling, never a floor ------------------


async def test_a_claim_expiry_beyond_the_policy_window_is_capped_not_honoured():
    """The constraint that stops §11b Option A decaying into the rejected option. If the
    IdP hook echoes an expiry the BFF asked for, a compromised BFF mints itself a long-lived
    elevation. The gateway computes the deadline from its own clock and its own policy."""
    now = time.time()
    grant = await _verify(raw=_grant(exp=int(now) + 30 * 86400), now=now)
    window = DEFAULT_GRANT_POLICIES[SCOPE_TOOLS_CALL].max_lifetime
    assert grant.expires_at <= now + window
    # And specifically: nowhere near the thirty days that was asked for.
    assert grant.expires_at < now + 2 * window


async def test_a_shorter_claim_expiry_is_honoured():
    """The claim may only tighten. An IdP that issues a 60-second grant gets 60 seconds —
    otherwise "may be shorter, never longer" is only half implemented, and the half that
    is missing is the one an operator would rely on."""
    now = time.time()
    grant = await _verify(raw=_grant(exp=int(now) + 60), now=now)
    assert grant.expires_at == pytest.approx(now + 60, abs=2)


async def test_an_already_expired_claim_is_refused():
    now = time.time()
    with pytest.raises(GrantError, match="expired"):
        await _verify(raw=_grant(exp=int(now) - 3600), now=now)


async def test_the_skew_tolerance_on_an_expired_grant_is_bounded_by_leeway():
    """``auth_time`` and any claim ``exp`` come from the IdP's clock, not this gateway's, so
    some tolerance is required — and it is the same ``leeway`` already applied to the token's
    own ``exp``. What matters is that it is *bounded*: a grant one leeway-width past its
    deadline is refused, so the tolerance cannot quietly become the window."""
    now = time.time()
    await _verify(raw=_grant(exp=int(now) - 5), leeway=60, now=now)  # inside skew
    with pytest.raises(GrantError, match="expired"):
        await _verify(raw=_grant(exp=int(now) - 90), leeway=60, now=now)
    # ...and a deployment that wants no tolerance at all gets none.
    with pytest.raises(GrantError, match="expired"):
        await _verify(raw=_grant(exp=int(now) - 5), leeway=0, now=now)


# --- Hazards 2 + 3: step-up must have happened, and happened recently ----------


async def test_a_token_without_the_step_up_acr_is_refused():
    """Hazard 2. The IdP was *asked* for a step-up and issued anyway — a request parameter
    is not an outcome."""
    with pytest.raises(GrantError, match="acr"):
        await _verify(acr="urn:mcp:password")


async def test_a_token_with_no_acr_at_all_is_refused():
    """A missing claim is not a satisfied one. This is the direction an implementation
    gets wrong for free: ``claims.get("acr")`` returning None and comparing unequal is
    correct only by accident, and one ``if acr and acr not in ...`` inverts it."""
    with pytest.raises(GrantError, match="acr"):
        await _verify(acr=None)


async def test_grants_are_refused_when_no_step_up_context_is_configured():
    """Fail closed on the *operator's* omission too. An issuer with no configured step-up
    context cannot have its step-up verified, so it cannot carry an elevation — rather
    than every grant sailing through because there is nothing to compare against."""
    with pytest.raises(GrantError, match="step_up_acr"):
        await _verify(step_up_acr=())


async def test_a_stale_step_up_is_refused():
    """Hazard 3. Stepping up three hours ago does not satisfy a step-up now; if it did,
    the window would renew on activity, which is §8's sliding window by another name."""
    now = time.time()
    with pytest.raises(GrantError, match="auth_time"):
        await _verify(auth_time=int(now) - 3 * 3600, now=now)


async def test_a_missing_auth_time_is_refused():
    with pytest.raises(GrantError, match="auth_time"):
        await _verify(auth_time=None)


async def test_an_auth_time_in_the_future_is_refused():
    """Otherwise the freshness check is trivially defeated from the same place the stale
    check is enforced — push ``auth_time`` forward and the window never closes."""
    now = time.time()
    with pytest.raises(GrantError, match="auth_time"):
        await _verify(auth_time=int(now) + 3600, now=now)


# --- Hazard 4: exactly one tenant, and it must be this one --------------------


async def test_a_grant_naming_another_tenant_is_refused():
    with pytest.raises(GrantError, match="tenant"):
        await _verify(raw=_grant(tenant="other-corp"))


async def test_a_grant_naming_no_tenant_is_refused():
    with pytest.raises(GrantError, match="tenant"):
        await _verify(raw=_grant(tenant=None))


async def test_a_grant_naming_several_tenants_is_refused():
    """§11a: exactly one tenant. A list is the natural way an estate-wide grant would be
    expressed, and it is spendable once *per gateway* — single-use across the estate is
    not a thing this architecture can express, by design (§1)."""
    with pytest.raises(GrantError, match="tenant"):
        await _verify(raw=_grant(tenant=[TENANT_ID, "other-corp"]))


async def test_a_wildcard_tenant_is_not_special():
    """ "*" is a string, so a naive equality check refuses it — but an implementation that
    grows a convenience branch for "all tenants" reintroduces exactly the estate-wide
    grant §11a rules out. Pinned so that branch has to delete a test to appear."""
    with pytest.raises(GrantError, match="tenant"):
        await _verify(raw=_grant(tenant="*"))


async def test_grants_are_refused_when_the_gateway_knows_no_tenant_identity():
    """A gateway that does not know its own name cannot check that a grant names *it*,
    so it must not honour grants at all. The alternative — accepting any well-formed
    grant — is the estate-wide grant arriving through a missing config value."""
    with pytest.raises(GrantError, match="tenant_id"):
        await _verify(tenant_id=None)


# --- §11c: the request selects a tenant, only the IdP authorizes one -----------
#
# The hazard measurement turned up, which no amount of reasoning about our own code would
# have: a requested `scope` is granted to whoever asks for it. An operator with no
# entitlement to a tenant requested that tenant's scope from a real IdP and received the
# claim. So the grant claim's `tenant` is chosen by the request — in practice by the BFF,
# which is inside the threat model — and asserts nothing on its own. The entitlement claim
# is the half the IdP derives from the directory, and the intersection is the real bound.


async def test_a_grant_for_a_tenant_the_operator_is_not_entitled_to_is_refused():
    """The whole point of §11c, and the case the old code accepted.

    Everything here is well-formed: a real step-up, a fresh auth_time, a grant naming
    *this* gateway's tenant. The only thing wrong is that this operator was never
    entitled to act on it — which is precisely what a requested scope cannot establish.
    """
    with pytest.raises(GrantError, match="not among the operator's entitled"):
        await _verify(entitlement=["globex", "initech"])


async def test_a_missing_entitlement_claim_is_refused():
    """An absent entitlement is not an unlimited one. If it were, an IdP that simply does
    not emit the claim would hand back exactly the pre-§11c behaviour, silently."""
    with pytest.raises(GrantError, match="no usable"):
        await _verify(entitlement=None)


@pytest.mark.parametrize("junk", [{}, 42, True, ["", None], [], ""])
async def test_a_malformed_or_empty_entitlement_claim_is_refused(junk):
    """Fail closed in every direction, including the shapes an IdP might plausibly emit
    for "none": an empty list, an empty string, a list of blanks."""
    with pytest.raises(GrantError):
        await _verify(entitlement=junk)


@pytest.mark.parametrize("empty", [[], "", ["", None]])
async def test_an_empty_entitlement_says_so_rather_than_blaming_the_tenant(empty):
    """ "Entitled to nothing" and "not entitled to *this*" are different operator
    problems - the first is usually a missing IdP mapping. The distinction is only a
    message, so it needs an assertion or it silently collapses into the other branch."""
    with pytest.raises(GrantError, match="entitled\\s+to none"):
        await _verify(entitlement=empty)


async def test_a_single_string_entitlement_is_honoured():
    """An IdP with one entitled tenant may emit a bare string rather than a list; that is
    a formatting difference, not a policy one."""
    grant = await _verify(entitlement=TENANT_ID)
    assert grant.tenant == TENANT_ID


async def test_junk_entries_cannot_manufacture_an_entitlement():
    """Filtering non-strings may only shrink the allowed set. A list of junk plus the
    right tenant still works; a list of junk alone must not."""
    assert (await _verify(entitlement=[None, 7, TENANT_ID])).tenant == TENANT_ID
    with pytest.raises(GrantError):
        await _verify(entitlement=[None, 7, {"tenant": TENANT_ID}])


async def test_an_unconfigured_entitlement_claim_refuses_rather_than_skips():
    """The check must not be optional. An issuer configured to honour grants with no
    entitlement claim named has nothing authorizing the tenant it was handed — the same
    hole §11c exists to close, arriving through a blank config value instead."""
    with pytest.raises(GrantError, match="entitlement_claim"):
        await _verify(entitlement_claim="")


async def test_entitlement_is_checked_before_a_single_use_grant_is_consumed(store):
    """Ordering, and it is load-bearing. If an unentitled operator's attempt burned the
    grant id, anyone could disarm a legitimate single-use credentials grant by presenting
    it once from an account entitled to nothing."""
    now = time.time()  # one step-up across both calls, or the second cannot collide anyway
    claim = _grant(id="grant-single", scopes=[SCOPE_BACKUP_READ])
    with pytest.raises(GrantError, match="not among the operator's entitled"):
        await _verify(raw=claim, store=store, entitlement=["globex"], now=now)
    # The id must still be spendable by the operator who is actually entitled to it.
    grant = await _verify(raw=claim, store=store, entitlement=[TENANT_ID], now=now)
    assert grant.single_use is True and grant.id == "grant-single"


async def test_entitlement_naming_other_tenants_does_not_widen_the_grant(rig):
    """Being entitled to three tenants does not make a grant estate-wide: the grant still
    names exactly one, and it still has to be this gateway's."""
    v, tenant_key, provider_key = rig
    tok = _token(
        provider_key,
        iss=PROVIDER_ISS,
        groups=["provider-admins"],
        **{
            "mcp_grant": _grant(tenant="globex"),
            ENTITLEMENT_CLAIM_DEFAULT: ["globex", TENANT_ID, "initech"],
        },
    )
    with pytest.raises(OIDCError, match="this gateway is tenant"):
        await v.validate(tok)


async def test_the_entitlement_claim_name_is_configurable(rig):
    """Deployments will not agree on the claim name; the check must follow the config."""
    v, tenant_key, provider_key = rig
    cfg = v.for_issuer(PROVIDER_ISS).config
    object.__setattr__(cfg, "entitlement_claim", "corp_tenants")
    tok = _token(
        provider_key,
        iss=PROVIDER_ISS,
        groups=["provider-admins"],
        # The default claim is removed, not merely shadowed: leaving a valid
        # `mcp_allowed_tenants` in the token lets an implementation that ignores the
        # config and reads the default name pass this test anyway. Mutation testing
        # caught exactly that.
        **{"mcp_grant": _grant(), "corp_tenants": [TENANT_ID], ENTITLEMENT_CLAIM_DEFAULT: None},
    )
    principal = await v.validate(tok)
    assert SCOPE_TOOLS_CALL in principal.scopes


async def test_the_entitlement_claim_name_is_read_from_config(rig):
    """The config *builder* must carry the name through, not just the dataclass default.

    Separate from the test above on purpose: that one sets the field on an already-built
    config, so an ``_issuer_config`` that ignored the key entirely would still pass it.
    Mutation testing found that gap.
    """
    from device_mcp_gateway.oidc import build_oidc_validator

    v = build_oidc_validator(
        {
            "gateway": {
                "tenant_id": TENANT_ID,
                "oidc": {
                    "enabled": True,
                    "issuers": [
                        {
                            "issuer": PROVIDER_ISS,
                            "audience": AUDIENCE,
                            "plane": PLANE_PROVIDER,
                            "group_roles": {"provider-admins": "operator"},
                            "step_up_acr": [STEP_UP_ACR],
                            "entitlement_claim": "corp_tenants",
                            "jwks_uri": f"{PROVIDER_ISS}/jwks",
                        }
                    ],
                },
            },
            "security": {"allow_private_targets": True},
        }
    )
    assert v.for_issuer(PROVIDER_ISS).config.entitlement_claim == "corp_tenants"


# --- Hazard 5: consumption fails closed ---------------------------------------


async def test_a_single_use_grant_is_accepted_once(store):
    raw = _grant(id="grant-cred", scopes=[SCOPE_BACKUP_READ])
    grant = await _verify(raw=raw, store=store)
    assert grant.single_use is True
    assert grant.scopes == frozenset({SCOPE_BACKUP_READ})


async def test_a_single_use_grant_is_refused_on_replay(store):
    """The property the whole consumption record exists for. An issued bearer token is
    replayable until expiry whichever client minted it (§11) — single use has to be
    enforced by state on the receiving side, and this is that state working."""
    # ``now`` is pinned so both calls derive the same ``auth_time`` and therefore describe
    # the *same* step-up. Left to the clock, a second boundary between the two calls would
    # make them two elevations and the replay would legitimately be allowed — an
    # intermittent green that says nothing about the property under test.
    now = time.time()
    raw = _grant(id="grant-cred", scopes=[SCOPE_BACKUP_READ])
    await _verify(raw=raw, store=store, now=now)
    with pytest.raises(GrantError, match="already been spent by this step-up"):
        await _verify(raw=raw, store=store, now=now)


async def test_a_non_single_use_grant_is_replayable_within_its_window(store):
    """The converse, stated so the two classes cannot silently collapse into one. A
    ``tools:call`` grant is a 15-minute window, not one call — §8's *initiation* rule. If
    a refactor made everything single-use, an operator's second request inside their own
    window would start failing, and only this test says that is wrong."""
    raw = _grant(id="grant-invoke", scopes=[SCOPE_TOOLS_CALL])
    await _verify(raw=raw, store=store)
    again = await _verify(raw=raw, store=store)
    assert again.scopes == frozenset({SCOPE_TOOLS_CALL})


async def test_two_different_single_use_grants_do_not_collide(store):
    """Two distinct grant ids stay distinct. Keyed on the subject or the tenant *alone*, a
    support engineer's second grant of the day is refused as a replay — which reads as a bug
    and gets 'fixed' by weakening the check.

    ``now`` is pinned so the two calls share a step-up: otherwise a differing ``auth_time``
    would separate them regardless of the id, and the test would pass without the id
    mattering at all.
    """
    now = time.time()
    await _verify(raw=_grant(id="g1", scopes=[SCOPE_BACKUP_READ]), store=store, now=now)
    grant = await _verify(raw=_grant(id="g2", scopes=[SCOPE_BACKUP_READ]), store=store, now=now)
    assert grant.id == "g2"


# --- what single use is consumed *against* (found against a real IdP, 2026-08-16) ---
#
# Everything above this line was written against hand-built claims, and hand-built claims
# always carried a distinct `id`. Attached to Keycloak, the claim arrives with a **constant**
# one — a hardcoded claim mapper is the only stock way to emit `mcp_grant.id`, and it emits
# the value it was configured with. Measured end to end: two legitimate elevations, each
# with its own fresh TOTP step-up, gave `backup:read` 200 and then 401 "already been spent".
# The credentials class worked exactly once per deployment, ever.
#
# The mechanism was not too strict; it was enforcing a different property from the one §8
# states. §8 says *one operation, re-entry by step-up*, so the thing consumption identifies
# has to be the elevation — subject, grant id and step-up time — not the label on the claim.


async def test_a_fresh_step_up_re_arms_a_grant_id_the_idp_reuses(store):
    """The regression, stated as the property that was missing. Two elevations, each with
    its own step-up, presenting the id a stock IdP mapper actually emits: both spend."""
    now = time.time()
    claim = _grant(id="kc-credentials-static", scopes=[SCOPE_BACKUP_READ])
    first = await _verify(raw=claim, store=store, auth_time=int(now) - 200, now=now)
    second = await _verify(raw=claim, store=store, auth_time=int(now) - 5, now=now)
    assert first.single_use is second.single_use is True
    assert first.id == second.id == "kc-credentials-static"


async def test_one_operator_spending_a_reused_id_does_not_disarm_another(store):
    """The other half of the same defect, and the reason the subject is in the key. With a
    constant id and no subject, the first operator to run a backup locks out every colleague
    who steps up afterwards — indistinguishable, from their side, from a broken feature."""
    now = time.time()
    claim = _grant(id="kc-credentials-static", scopes=[SCOPE_BACKUP_READ])
    await _verify(raw=claim, store=store, subject=f"oidc:{PROVIDER_ISS}#alice", now=now)
    grant = await _verify(raw=claim, store=store, subject=f"oidc:{PROVIDER_ISS}#bob", now=now)
    assert grant.single_use is True


async def test_a_refreshed_token_does_not_buy_a_second_credentials_operation(rig):
    """Why the record is keyed on ``auth_time`` and **not** the token id.

    ``jti`` is the intuitive key and it is unsound: a refresh mints a new token id from the
    *same* authentication event, carrying the same ``acr``, the same ``auth_time`` and the
    same grant claim. Keyed on ``jti``, single use becomes once-per-refresh — defeated from
    inside the window it is supposed to hold across. Written at the token level because
    that is the only place a second token from one login can be expressed at all.
    """
    v, _, provider_key = rig
    auth_time = int(time.time()) - 30
    claim = _grant(id="kc-credentials-static", scopes=[SCOPE_BACKUP_READ])
    common = dict(iss=PROVIDER_ISS, groups=["provider-admins"], mcp_grant=claim, auth_time=auth_time)
    principal = await v.validate(_token(provider_key, jti="access-token-1", **common))
    assert SCOPE_BACKUP_READ in principal.scopes
    with pytest.raises(OIDCError, match="already been spent"):
        await v.validate(_token(provider_key, jti="access-token-2", **common))


async def test_two_operators_sharing_a_constant_grant_id_each_get_their_operation(rig):
    """The same property as the unit test above, but through the authenticator, which is
    where the subject is actually plumbed. Nothing else pins that ``principal.subject`` —
    and not the issuer, or a constant, or the raw ``sub`` — is what reaches the record."""
    v, _, provider_key = rig
    auth_time = int(time.time()) - 30
    claim = _grant(id="kc-credentials-static", scopes=[SCOPE_BACKUP_READ])
    common = dict(iss=PROVIDER_ISS, groups=["provider-admins"], mcp_grant=claim, auth_time=auth_time)
    first = await v.validate(_token(provider_key, sub="alice", **common))
    second = await v.validate(_token(provider_key, sub="bob", **common))
    assert SCOPE_BACKUP_READ in first.scopes and SCOPE_BACKUP_READ in second.scopes


async def test_how_auth_time_is_encoded_does_not_split_one_elevation(store):
    """``1700000000`` and ``1700000000.0`` are one step-up. Unnormalised they hash apart,
    and single use would depend on whether the IdP's JSON encoder emitted a decimal point."""
    now = time.time()
    claim = _grant(id="g-cred", scopes=[SCOPE_BACKUP_READ])
    await _verify(raw=claim, store=store, auth_time=int(now) - 30, now=now)
    with pytest.raises(GrantError, match="already been spent"):
        await _verify(raw=claim, store=store, auth_time=float(int(now) - 30), now=now)


async def test_the_consumption_identity_cannot_be_re_cut_between_its_fields(store):
    """The hashed material is length-prefixed, so no pair of distinct elevations shares a
    digest. The separator alone covers every realistic subject; the prefix is what makes the
    encoding unambiguous for *any* string, which is the only thing a hash input can safely
    assume. Falsifiable rather than asserted — hence a subject carrying the separator."""
    now = time.time()
    scopes = [SCOPE_BACKUP_READ]
    await _verify(raw=_grant(id="c", scopes=scopes), subject="oidc:i#a\x00b", store=store, now=now)
    grant = await _verify(raw=_grant(id="b\x00c", scopes=scopes), subject="oidc:i#a", store=store, now=now)
    assert grant.single_use is True


@pytest.mark.parametrize("bad", [None, "", 7, ["oidc:i#a"]])
async def test_a_grant_with_no_authenticated_subject_is_refused(bad):
    """An elevation belongs to one operator — it is audited against them and consumed
    against them. Honouring a grant with no subject would merge every operator's single-use
    record into one, which is the "constant id" defect rebuilt from the other end."""
    with pytest.raises(GrantError, match="no authenticated subject"):
        await _verify(subject=bad)


async def test_the_consumption_record_carries_no_operator_identifier():
    """A `sub` is routinely an email address, and Redis key names surface in `SCAN` output,
    slow logs and support dumps. The store therefore receives a digest, not the material."""
    seen: list[str] = []

    class _Recorder:
        async def consume(self, consumption_id, *, ttl):
            seen.append(consumption_id)
            return True

    await _verify(
        raw=_grant(id="g-cred", scopes=[SCOPE_BACKUP_READ]),
        subject=f"oidc:{PROVIDER_ISS}#alice@example.com",
        store=_Recorder(),
    )
    assert len(seen) == 1
    assert "alice@example.com" not in seen[0] and "g-cred" not in seen[0]
    assert len(seen[0]) == 64 and set(seen[0]) <= set("0123456789abcdef")


async def test_a_consumption_store_that_raises_refuses_the_grant():
    """ADR-0006 fail-closed, at the point where it is most tempting to be lenient. If a
    write failure let the grant through, single-use would degrade to replayable-until-expiry
    exactly when Redis is unhealthy — the moment an operator is least likely to notice."""

    class _Broken:
        async def consume(self, grant_id, *, ttl):
            raise RuntimeError("redis unavailable")

    with pytest.raises(GrantError, match="consum"):
        await _verify(raw=_grant(scopes=[SCOPE_BACKUP_READ]), store=_Broken())


async def test_no_store_at_all_refuses_every_grant_not_only_single_use_ones():
    """Embedded mode. §11a refuses *an elevated grant* with no shared store, not merely
    the single-use ones — a gateway with no consumption store cannot enforce the property
    that made the checked claim preferable to a configured issuer in the first place."""
    for scope in (SCOPE_BACKUP_READ, SCOPE_TOOLS_CALL):
        with pytest.raises(GrantError, match="store"):
            await _verify(raw=_grant(scopes=[scope]), store=None)


async def test_consumption_happens_only_after_every_other_check_passes(store):
    """A grant refused for an unrelated reason must not burn its id, or a clock-skew blip
    turns a legitimate single-use grant into one the operator can never spend."""
    raw = _grant(id="grant-cred", scopes=[SCOPE_BACKUP_READ])
    with pytest.raises(GrantError, match="acr"):
        await _verify(raw=raw, acr="urn:mcp:password", store=store)
    grant = await _verify(raw=raw, store=store)  # the id was never consumed
    assert grant.id == "grant-cred"


# --- Hazard 7: the claim's scope range is closed ------------------------------


async def test_a_claim_naming_a_bff_scope_is_refused():
    """§11's one remaining line: the gateway never learns the provider scope vocabulary.
    ``provider:invoke`` is a BFF scope; arriving here it is simply an unknown string, and
    the failure must be loud rather than a silently empty grant."""
    with pytest.raises(GrantError, match="provider:invoke"):
        await _verify(raw=_grant(scopes=["provider:invoke"]))


async def test_a_claim_naming_an_unknown_scope_is_refused():
    with pytest.raises(GrantError, match="nonsense"):
        await _verify(raw=_grant(scopes=["nonsense"]))


async def test_a_claim_naming_a_scope_already_inside_the_ceiling_is_refused():
    """``devices:read`` needs no grant — a claim asking for one means the minting side
    misunderstands the model, and answering "granted" would confirm the misunderstanding.
    Refusing keeps the grantable set and the §5a carve-out the same set."""
    with pytest.raises(GrantError, match=SCOPE_DEVICES_READ):
        await _verify(raw=_grant(scopes=[SCOPE_DEVICES_READ]))


async def test_an_empty_scope_list_is_refused():
    """A grant that grants nothing is a malformed grant, not a no-op: it would be audited
    as an elevation that never happened."""
    with pytest.raises(GrantError, match="scopes"):
        await _verify(raw=_grant(scopes=[]))


async def test_a_claim_that_is_not_an_object_is_refused():
    for raw in ("grant-001", ["grant-001"], 42):
        with pytest.raises(GrantError):
            await _verify(raw=raw)


async def test_a_claim_with_no_id_is_refused():
    """Without an id there is nothing to consume against and nothing to audit — the two
    things the grant exists to make possible."""
    with pytest.raises(GrantError, match="id"):
        await _verify(raw=_grant(id=""))


async def test_a_mixed_grant_takes_the_strictest_policy(store):
    """Composition is fail-safe, not first-wins. A claim naming both classes is single-use
    and gets the shorter window — the alternative is that adding ``tools:call`` to a
    credentials grant *relaxes* it."""
    now = time.time()
    raw = _grant(id="mixed", scopes=[SCOPE_TOOLS_CALL, SCOPE_BACKUP_READ])
    grant = await _verify(raw=raw, store=store, now=now)
    assert grant.single_use is True
    # ...and the *window* composes the same way, which the single-use half does not imply:
    # `min` and `max` over the two policies both produce a working grant, and only this
    # pins which one. Anchored on the same auth_time `_verify` uses.
    auth_time = int(now) - 30
    assert grant.expires_at == auth_time + DEFAULT_GRANT_POLICIES[SCOPE_BACKUP_READ].max_lifetime
    assert grant.expires_at < auth_time + DEFAULT_GRANT_POLICIES[SCOPE_TOOLS_CALL].max_lifetime
    with pytest.raises(GrantError, match="already"):
        await _verify(raw=raw, store=store, now=now)


# --- end to end, through the validator ----------------------------------------


def _cfg(issuer: str, *, plane: str, group_roles: dict[str, str], **over) -> OIDCConfig:
    params = dict(
        issuer=issuer,
        audience=AUDIENCE,
        group_roles=group_roles,
        plane=plane,
        jwks_uri=f"{issuer}/jwks",
        allow_private_targets=True,  # no DNS resolution → fully offline
        tenant_id=TENANT_ID,
        step_up_acr=(STEP_UP_ACR,),
    )
    params.update(over)
    return OIDCConfig(**params)


def _token(priv: rsa.RSAPrivateKey, *, iss: str, kid: str = "key-1", sub: str = "opsuser", groups=None, **over) -> str:
    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": iss,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "auth_time": now - 30,
        "acr": STEP_UP_ACR,
        "groups": groups if groups is not None else [],
        # §11c: the IdP's directory-derived statement of the operator's entitled tenants.
        # Present by default so the grant tests below fail for their own reason; the §11c
        # tests override it explicitly.
        ENTITLEMENT_CLAIM_DEFAULT: [TENANT_ID],
    }
    claims.update(over)
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def rig():
    """A tenant issuer and a provider issuer, both with a grant store attached, seeded
    offline. The provider group maps to ``operator`` — the §5a everyday grant, which is
    below ``tools:call`` and every ``backup:*`` scope. That gap is what a grant lifts."""
    tenant_key, provider_key = _keypair(), _keypair()
    v = MultiIssuerValidator(
        [
            _cfg(TENANT_ISS, plane=PLANE_TENANT, group_roles={"tenant-viewers": "viewer"}),
            _cfg(PROVIDER_ISS, plane=PLANE_PROVIDER, group_roles={"provider-admins": "operator"}),
        ]
    )
    v.seed(TENANT_ISS, {"keys": [_jwk(tenant_key, "key-1")]})
    v.seed(PROVIDER_ISS, {"keys": [_jwk(provider_key, "key-1")]})
    v.attach_grant_store(MemoryGrantStore())
    return v, tenant_key, provider_key


async def test_provider_token_without_a_grant_stays_under_the_ceiling(rig):
    """The baseline the grant is measured against. Without this, a test showing the grant
    adds ``tools:call`` proves nothing — the scope might have been there all along."""
    v, _, provider_key = rig
    p = await v.validate(_token(provider_key, iss=PROVIDER_ISS, groups=["provider-admins"]))
    assert p.scopes == frozenset({SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_METRICS_READ})
    assert p.grant_id is None


async def test_a_grant_raises_the_ceiling_for_that_request(rig):
    v, _, provider_key = rig
    token = _token(provider_key, iss=PROVIDER_ISS, groups=["provider-admins"], mcp_grant=_grant())
    p = await v.validate(token)
    assert SCOPE_TOOLS_CALL in p.scopes
    # ...and only that. The grant lifts the ceiling for what it names, not to `admin`.
    assert not p.scopes & {SCOPE_BACKUP_READ, SCOPE_BACKUP_EXPORT_PORTABLE}
    assert p.grant_id == "grant-001"
    # The grant is a *union* with what the role already allowed, not a replacement. Both
    # produce a principal holding `tools:call`, so nothing above separates them — but the
    # replacement reading strips an elevated operator of the everyday scopes they had a
    # second earlier, so elevating to call a tool would cost them `devices:read` while
    # they did it. Enumerated rather than spot-checked so the base set cannot shrink here
    # unnoticed either.
    assert p.scopes == frozenset({SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_METRICS_READ, SCOPE_TOOLS_CALL})


async def test_the_elevation_is_not_ambient_on_the_next_request(rig):
    """§4: exercised, not held. The same token without the claim gets the base scopes back
    — the grant lives on the request, not on a session the gateway remembers."""
    v, _, provider_key = rig
    await v.validate(_token(provider_key, iss=PROVIDER_ISS, groups=["provider-admins"], mcp_grant=_grant()))
    p = await v.validate(_token(provider_key, iss=PROVIDER_ISS, groups=["provider-admins"]))
    assert SCOPE_TOOLS_CALL not in p.scopes


async def test_a_grant_on_a_tenant_issuer_grants_nothing(rig):
    """Hazard 6, and the one most likely to be got backwards. The tenant plane has no
    ceiling, so there is nothing to *lift* — but a union applied before the plane is
    consulted hands a tenant `viewer` full tool invocation on their own stack, sourced
    from their own IdP. The claim must be ignored, and the principal unchanged."""
    v, tenant_key, _ = rig
    token = _token(tenant_key, iss=TENANT_ISS, groups=["tenant-viewers"], mcp_grant=_grant())
    p = await v.validate(token)
    assert p.scopes == frozenset({SCOPE_DEVICES_READ, SCOPE_METRICS_READ})
    assert SCOPE_TOOLS_CALL not in p.scopes
    assert p.grant_id is None


async def test_an_invalid_grant_refuses_the_whole_token(rig):
    """Not "authenticate without the elevation". A caller presenting a grant is asking to
    act elevated; silently serving them the unelevated principal means the *next* check
    they hit is a 403 on the route, which reads as a permissions bug rather than a rejected
    grant — and an expired credentials grant would look identical to a typo."""
    v, _, provider_key = rig
    token = _token(
        provider_key,
        iss=PROVIDER_ISS,
        groups=["provider-admins"],
        mcp_grant=_grant(tenant="other-corp"),
    )
    with pytest.raises(OIDCError, match="grant"):
        await v.validate(token)


async def test_a_grant_cannot_rescue_an_unmapped_group(rig):
    """The grant lifts a *ceiling*; it is not an alternative route to authority. Someone
    whose groups map to nothing is authenticated with no scopes, and a grant claim must not
    turn that into `tools:call` — otherwise the group mapping stops being load-bearing for
    exactly the population §6a exists to constrain."""
    v, _, provider_key = rig
    token = _token(provider_key, iss=PROVIDER_ISS, groups=["unmapped-group"], mcp_grant=_grant())
    p = await v.validate(token)
    assert p.scopes == frozenset()
    assert p.grant_id is None


async def test_a_provider_token_with_no_store_attached_refuses_the_grant():
    """Embedded mode end to end: the validator is built at import time, before Redis
    exists, so "no store attached" is the real state a misordered startup would leave it
    in — and it must refuse rather than fall back to honouring the claim."""
    provider_key = _keypair()
    v = MultiIssuerValidator([_cfg(PROVIDER_ISS, plane=PLANE_PROVIDER, group_roles={"provider-admins": "operator"})])
    v.seed(PROVIDER_ISS, {"keys": [_jwk(provider_key, "key-1")]})
    token = _token(provider_key, iss=PROVIDER_ISS, groups=["provider-admins"], mcp_grant=_grant())
    with pytest.raises(OIDCError, match="grant"):
        await v.validate(token)


async def test_a_custom_grant_claim_name_is_honoured():
    """The claim name is per-issuer config: an IdP's custom-claims hook may be constrained
    to a namespaced name. Pinned because a hardcoded ``mcp_grant`` would work in every test
    above and fail only against a real IdP."""
    provider_key = _keypair()
    v = MultiIssuerValidator(
        [
            _cfg(
                PROVIDER_ISS,
                plane=PLANE_PROVIDER,
                group_roles={"provider-admins": "operator"},
                grant_claim="https://mcp.example/grant",
            )
        ]
    )
    v.seed(PROVIDER_ISS, {"keys": [_jwk(provider_key, "key-1")]})
    v.attach_grant_store(MemoryGrantStore())
    token = _token(
        provider_key,
        iss=PROVIDER_ISS,
        groups=["provider-admins"],
        **{"https://mcp.example/grant": _grant()},
    )
    p = await v.validate(token)
    assert SCOPE_TOOLS_CALL in p.scopes


async def test_a_provider_issuer_without_a_tenant_id_is_refused_at_startup():
    """Fail fast, not on the first elevation. A provider-plane issuer whose gateway has no
    tenant identity can never honour a grant, and finding that out during an incident — the
    only time an elevation is wanted — is the worst possible moment."""
    with pytest.raises(ValueError, match="tenant_id"):
        _cfg(PROVIDER_ISS, plane=PLANE_PROVIDER, group_roles={"provider-admins": "operator"}, tenant_id=None)


async def test_a_tenant_issuer_needs_no_tenant_id():
    """The converse, so the startup guard cannot be widened into breaking every existing
    single-issuer deployment: a tenant-plane issuer honours no grants, so it has nothing to
    check a tenant id against."""
    cfg = _cfg(TENANT_ISS, plane=PLANE_TENANT, group_roles={"tenant-viewers": "viewer"}, tenant_id=None)
    assert cfg.tenant_id is None


# --- §11 audit: which records name the grant, and which must not change shape --------
#
# The grant is what let this request happen, so the records it produced have to say so —
# otherwise reconstructing an elevated session after the fact means correlating on subject
# and timestamp across a provider identity that is, by §5a design, doing ordinary everyday
# work under the same subject the rest of the time.
#
# Two shapes matter and they pull against each other: the field must appear wherever a
# grant was used, and must not appear anywhere else. `audit_request` is the chokepoint for
# the credentials class (`backup:*` routes all go through it) but explicitly **not** for the
# invoke class — `tools:call` dispatch records are emitted through `audit_log` directly in
# four transport modules, which is exactly the class §8 makes replayable within its window
# and therefore the class whose records most need the join key.


def _req(principal=None, rid="r-1"):
    """A request stand-in with the two attributes the audit helpers actually read."""
    return SimpleNamespace(state=SimpleNamespace(principal=principal, request_id=rid))


def _granted(grant_id="grant-001"):
    return Principal(
        subject="oidc:https://provider-idp.example.com#u-1",
        scopes=frozenset({SCOPE_TOOLS_CALL}),
        auth_method="oidc",
        grant_id=grant_id,
    )


@pytest.fixture
def audit_records():
    """Capture emitted audit records (event='audit') as a list of ``extra`` dicts."""
    captured = []

    def _sink(message):
        if message.record["extra"].get("event") == "audit":
            captured.append(message.record["extra"])

    sink_id = logger.add(_sink, level="INFO")
    yield captured
    logger.remove(sink_id)


async def test_a_request_under_a_grant_is_audited_with_the_grant_id(audit_records):
    audit_request(_req(_granted()), "device.update", outcome="success", target="dev.local")
    assert audit_records[-1]["grant"] == "grant-001"


async def test_an_unelevated_request_carries_no_grant_field_at_all(audit_records):
    """Not ``grant=None``. The hash chain commits to the record's field *set*, so an
    always-present field would make every record from here on differ in shape from every
    record already written — for a value that says nothing. Absence is the signal, and
    this is what keeps existing chains verifying across the upgrade."""
    audit_request(_req(_granted(grant_id=None)), "device.update", outcome="success")
    assert "grant" not in audit_records[-1]


async def test_an_unauthenticated_request_audits_without_raising(audit_records):
    """The audit emitter observes the request; it must never be the thing that 500s it.
    A request refused *before* authentication has no principal at all, and those refusals
    are precisely the records worth having."""
    audit_request(_req(principal=None), "device.create", outcome="denied")
    assert "grant" not in audit_records[-1]
    assert audit_records[-1]["subject"] == "unauthenticated"


async def test_grant_fields_ignores_a_non_string_grant_id():
    """Belt and braces on the boundary between a claim and a log line: `grant_id` is set
    from a verified claim, but a field that reaches the audit sink is worth type-checking
    at the sink, because a chained record cannot be corrected afterwards."""
    assert grant_fields(_req(SimpleNamespace(grant_id=["g-1"]))) == {}
    assert grant_fields(_req(SimpleNamespace(grant_id=""))) == {}
    assert grant_fields(_req(SimpleNamespace(grant_id="g-1"))) == {"grant": "g-1"}


async def test_every_tool_dispatch_record_names_the_grant():
    """The invoke class's records, which `audit_request` does not reach.

    Asserted structurally over the source because that is the shape of the property: the
    four transport modules each emit their own dispatch record through `audit_log`, and the
    regression to catch is not a wrong value but an *omission* — a fifth site added later,
    or the kwarg dropped from one of the four while the other three keep the test green.
    A behavioural test per site would need a stood-up distributed transport each time and
    would still say nothing about the site nobody has written yet.

    §8 makes the invoke grant replayable within its window, so one grant id legitimately
    spans several of these records. That is the point: the id is the join key, and a
    dispatch record missing it drops out of the reconstruction silently.
    """
    missing = []
    for name in ("sse.py", "fleet.py", "streamable.py", "streamable_fleet.py"):
        path = Path(device_mcp_gateway.__file__).parent / "api" / name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "audit_log"):
                continue
            message = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else ""
            if "dispatch" not in str(message):
                continue
            passes_grant = any(
                kw.arg is None and isinstance(kw.value, ast.Call) and getattr(kw.value.func, "id", "") == "grant_fields"
                for kw in node.keywords
            )
            if not passes_grant:
                missing.append(f"{name}:{node.lineno} {message!r}")
    assert not missing, "tool-dispatch audit records that would not name an elevated grant:\n" + "\n".join(missing)


# --- §11a consumption against the store production actually uses ----------------
#
# Everything above consumes against `MemoryGrantStore`, which is the right double for the
# *policy* — but it is also a store this repo wrote, and a test that only ever exercises it
# agrees with itself about atomicity. `RedisGrantStore` is what a distributed gateway
# attaches, and its single-use property is one Redis flag (`NX`) deep: drop it and every
# `SET` succeeds, single-use silently becomes replayable-until-expiry, and no test above
# notices. fakeredis is not enough here either — the point is the real server's
# atomic-claim semantics under concurrency, which a simulator would model rather than run.


@pytest.mark.integration
async def test_redis_backed_single_use_is_claimed_exactly_once(real_redis):
    store = RedisGrantStore(real_redis)
    assert await store.consume("g-real", ttl=60) is True
    assert await store.consume("g-real", ttl=60) is False


@pytest.mark.integration
async def test_concurrent_replays_of_one_grant_produce_exactly_one_winner(real_redis):
    """The race the `NX` is there for: two gateway replicas presented the same credentials
    grant at the same instant. Sequential replay (above) is satisfied by a read-then-write
    that a simultaneous pair would both pass, so the concurrent case is asserted separately."""
    store = RedisGrantStore(real_redis)
    results = await asyncio.gather(*(store.consume("g-race", ttl=60) for _ in range(20)))
    assert sum(results) == 1


@pytest.mark.integration
async def test_the_consumption_record_expires_with_the_grant(real_redis):
    """A record kept forever would accumulate a key per grant for nothing — a grant past
    its deadline is refused by the clock check before consumption is ever reached. Asserted
    on the real server because a missing TTL is invisible to an in-process dict."""
    store = RedisGrantStore(real_redis)
    await store.consume("g-ttl", ttl=45)
    ttl = await real_redis.ttl(KEYS.grant_consumed("g-ttl"))
    assert 0 < ttl <= 45


@pytest.mark.integration
async def test_a_redis_that_refuses_the_write_refuses_the_grant(real_redis):
    """Fail closed, on the real client's own error type. `verify_grant`'s handler catches
    `Exception`, which is broad enough to be worth pinning against a store that raises the
    way the actual library does rather than the way a test double was written to."""

    class _Broken:
        async def set(self, *a, **kw):
            raise ConnectionError("connection pool exhausted")

    with pytest.raises(GrantError, match="could not record consumption"):
        await _verify(
            raw=_grant(id="g-broken", scopes=[SCOPE_BACKUP_READ]),
            store=RedisGrantStore(_Broken()),
        )
