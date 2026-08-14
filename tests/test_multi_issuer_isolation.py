# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0013 §6/§6a — a tenant gateway trusting a second (provider) issuer.

**This file was written before the implementation, deliberately.** Every test here is an
isolation property that fails *silently* if it regresses: the token still validates, the
request still succeeds, and the only symptom is that someone had authority they should not
have had. Nothing else in the suite would notice.

The four hazards, each of which the obvious implementation walks straight into:

1. **Cross-issuer key acceptance.** The natural way to accept two issuers is
   ``jwt.decode(..., issuer=[a, b])`` over one merged key set. That accepts a token signed
   by issuer A's key while claiming ``iss: B`` — a complete impersonation primitive. The
   issuer must be resolved *first*, from the unverified header, and the decode pinned to
   that single issuer with only that issuer's keys.
2. **Shared JWKS cache.** One ``kid``-keyed dict across issuers means issuer A's key can
   answer a lookup made on issuer B's behalf. ``kid`` is issuer-chosen and collisions are
   not exotic — ``key-1`` is a plausible value at both.
3. **Flat ``group_roles``.** ADR-0013 §6a's escalation, stated there and asserted here: a
   tenant's own IdP administrator creates a group named whatever the provider mapping keys
   on, adds themselves, and their own gateway hands them provider-level scopes.
4. **Colliding subjects.** ``oidc:{sub}`` conflates ``sub=admin`` at the tenant IdP with
   ``sub=admin`` at the provider IdP — one identity in the hash-chained audit, and in
   anything else keyed on the subject. This is the predicted defect class for this work:
   *a key missing a discriminator*.

Real RSA keys throughout, seeded into the caches, so the whole file runs offline.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from device_mcp_gateway.oidc import (
    PLANE_PROVIDER,
    PLANE_TENANT,
    MultiIssuerValidator,
    OIDCConfig,
    OIDCError,
    build_oidc_validator,
)
from device_mcp_gateway.rbac import (
    SCOPE_BACKUP_EXPORT_PORTABLE,
    SCOPE_BACKUP_READ,
    SCOPE_DEVICES_READ,
    SCOPE_DEVICES_WRITE,
    SCOPE_METRICS_READ,
    SCOPE_TOOLS_CALL,
)

TENANT_ISS = "https://tenant-idp.example.com"
PROVIDER_ISS = "https://provider-idp.example.com"
AUDIENCE = "device-mcp-gateway"


def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(priv: rsa.RSAPrivateKey, kid: str) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    return jwk


def _cfg(issuer: str, *, plane: str, group_roles: dict[str, str], **over) -> OIDCConfig:
    params = dict(
        issuer=issuer,
        audience=AUDIENCE,
        group_roles=group_roles,
        plane=plane,
        jwks_uri=f"{issuer}/jwks",
        allow_private_targets=True,  # no DNS resolution → fully offline
    )
    params.update(over)
    return OIDCConfig(**params)


def _token(priv: rsa.RSAPrivateKey, *, iss: str, kid: str, sub: str = "alice", groups=None, **over) -> str:
    claims = {
        "sub": sub,
        "iss": iss,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "groups": groups if groups is not None else [],
    }
    claims.update(over)
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def rig():
    """Two issuers, two independent keypairs, seeded offline.

    Deliberately gives both issuers the **same `kid`** — `key-1` is a plausible value at
    any IdP, and a shared cache is only obviously wrong once the kids collide.
    """
    tenant_key, provider_key = _keypair(), _keypair()
    tenant = _cfg(
        TENANT_ISS,
        plane=PLANE_TENANT,
        group_roles={"mcp-admins": "admin", "mcp-viewers": "viewer"},
    )
    provider = _cfg(
        PROVIDER_ISS,
        plane=PLANE_PROVIDER,
        # §5a: the everyday provider debugging grant. Not `admin` — see the ceiling tests.
        group_roles={"provider-admins": "operator"},
    )
    v = MultiIssuerValidator([tenant, provider])
    v.seed(TENANT_ISS, {"keys": [_jwk(tenant_key, "key-1")]})
    v.seed(PROVIDER_ISS, {"keys": [_jwk(provider_key, "key-1")]})
    return v, tenant_key, provider_key


# --- Hazard 1 + 2: keys never cross an issuer boundary ------------------------


@pytest.mark.asyncio
async def test_tenant_key_cannot_sign_a_token_claiming_the_provider_issuer(rig):
    """The impersonation primitive. A tenant IdP operator signs with their own key and
    claims to be the provider IdP. If the decode accepts a *list* of issuers, this passes
    and a tenant mints themselves provider identity on their own gateway."""
    v, tenant_key, _ = rig
    forged = _token(tenant_key, iss=PROVIDER_ISS, kid="key-1", groups=["provider-admins"])
    with pytest.raises(OIDCError):
        await v.validate(forged)


@pytest.mark.asyncio
async def test_provider_key_cannot_sign_a_token_claiming_the_tenant_issuer(rig):
    """The converse, asserted separately — ADR-0013 §6a requires refusal in both
    directions, and an implementation can easily get one right and not the other."""
    v, _, provider_key = rig
    forged = _token(provider_key, iss=TENANT_ISS, kid="key-1", groups=["mcp-admins"])
    with pytest.raises(OIDCError):
        await v.validate(forged)


@pytest.mark.asyncio
async def test_each_issuer_still_validates_its_own_token(rig):
    """The control. Without this the two tests above would pass on an implementation that
    simply rejects everything."""
    v, tenant_key, provider_key = rig
    tp = await v.validate(_token(tenant_key, iss=TENANT_ISS, kid="key-1", groups=["mcp-viewers"]))
    pp = await v.validate(_token(provider_key, iss=PROVIDER_ISS, kid="key-1", groups=["provider-admins"]))
    assert SCOPE_DEVICES_READ in tp.scopes
    assert SCOPE_DEVICES_WRITE in pp.scopes


@pytest.mark.asyncio
async def test_jwks_caches_are_not_shared_between_issuers(rig):
    """Asserted on the cache itself, not only through validate().

    A merged cache would still pass the forgery tests above if the decode pinned the
    issuer — but it leaves the wrong key reachable for the next change to trip over.
    """
    v, tenant_key, provider_key = rig
    tenant_jwk = await v.for_issuer(TENANT_ISS).jwks.get_key("key-1")
    provider_jwk = await v.for_issuer(PROVIDER_ISS).jwks.get_key("key-1")
    assert tenant_jwk["n"] != provider_jwk["n"], "same kid resolved to the same key across issuers"


# --- Hazard 3: group mappings never cross an issuer boundary ------------------


@pytest.mark.asyncio
async def test_a_tenant_group_named_like_the_provider_mapping_grants_nothing(rig):
    """ADR-0013 §6a's escalation, stated in the ADR and enforced here.

    The tenant IdP admin controls their own group names. Naming one `provider-admins`
    must not reach the provider issuer's mapping.
    """
    v, tenant_key, _ = rig
    p = await v.validate(_token(tenant_key, iss=TENANT_ISS, kid="key-1", groups=["provider-admins"]))
    assert p.scopes == frozenset(), f"tenant group borrowed the provider mapping: {sorted(p.scopes)}"


@pytest.mark.asyncio
async def test_a_provider_group_named_like_the_tenant_mapping_grants_nothing(rig):
    """The converse. `mcp-admins` maps to gateway `admin` for the tenant; from the
    provider issuer it must map to nothing at all."""
    v, _, provider_key = rig
    p = await v.validate(_token(provider_key, iss=PROVIDER_ISS, kid="key-1", groups=["mcp-admins"]))
    assert p.scopes == frozenset()


@pytest.mark.asyncio
async def test_there_is_no_shared_fallback_mapping(rig):
    """An unmapped (issuer, group) pair grants nothing — no global table consulted
    second, which is how a "sensible default" would quietly reintroduce the flat map."""
    v, tenant_key, _ = rig
    p = await v.validate(_token(tenant_key, iss=TENANT_ISS, kid="key-1", groups=["some-other-group"]))
    assert p.scopes == frozenset()


# --- Hazard 4: subjects carry their issuer -----------------------------------


@pytest.mark.asyncio
async def test_same_sub_at_two_issuers_yields_two_distinct_principals(rig):
    """The predicted defect class for this work: a key missing a discriminator.

    `sub=admin` is not globally unique — it is unique *within* an issuer. Conflating them
    puts two different humans on one line of the tenant's hash-chained audit, and the
    failure is invisible because both requests succeed.
    """
    v, tenant_key, provider_key = rig
    t = await v.validate(_token(tenant_key, iss=TENANT_ISS, kid="key-1", sub="admin", groups=["mcp-viewers"]))
    p = await v.validate(_token(provider_key, iss=PROVIDER_ISS, kid="key-1", sub="admin", groups=["provider-admins"]))
    assert t.subject != p.subject, f"issuers collapsed into one identity: {t.subject}"
    # And the issuer must be recoverable from the record, not merely different.
    assert TENANT_ISS in t.subject and PROVIDER_ISS in p.subject


# --- Routing: an unknown issuer is refused before any crypto ------------------


@pytest.mark.asyncio
async def test_token_from_an_unconfigured_issuer_is_rejected_by_routing(rig):
    """Asserts *why* it is rejected, not merely that it is.

    Found by mutation: routing every token to the first configured validator still ends in
    a rejection, because the per-issuer decode pins its own ``issuer=``. The token is safe
    either way — but a test that accepts any rejection cannot tell the two apart, so the
    routing control could be deleted and nothing would fail. Matching the message is what
    makes the primary control load-bearing rather than merely present.
    """
    v, tenant_key, _ = rig
    t = _token(tenant_key, iss="https://attacker.example.com", kid="key-1", groups=["mcp-admins"])
    with pytest.raises(OIDCError, match="not configured"):
        await v.validate(t)


@pytest.mark.asyncio
async def test_token_with_no_iss_claim_is_rejected_before_a_validator_is_chosen(rig):
    """There is nothing to route on, so there is no safe default. Falling back to "the
    first configured issuer" would be the same bug as a shared key set — and, as above,
    the downstream ``require: ["iss"]`` would mask it from a test that only asserts
    rejection."""
    v, tenant_key, _ = rig
    claims = {"sub": "alice", "aud": AUDIENCE, "exp": int(time.time()) + 300, "groups": ["mcp-admins"]}
    t = jwt.encode(claims, tenant_key, algorithm="RS256", headers={"kid": "key-1"})
    with pytest.raises(OIDCError, match="no usable iss"):
        await v.validate(t)


# --- §6a: issuer identity binds the eligible scope set, server-side ----------


def test_provider_plane_config_refuses_a_role_beyond_its_ceiling():
    """§5a and §5b as a startup check rather than a documentation promise.

    `provider:admin` must not become gateway `admin`, and no `backup:*` scope sits inside
    it at any level — because the provider holds `MCP_SECRET_KEY`, so for them a
    ciphertext archive and a portable one are equally a credential dump.
    """
    with pytest.raises(ValueError, match="plane"):
        _cfg(PROVIDER_ISS, plane=PLANE_PROVIDER, group_roles={"provider-admins": "admin"})
    with pytest.raises(ValueError, match="plane"):
        _cfg(PROVIDER_ISS, plane=PLANE_PROVIDER, group_roles={"provider-backup": "backup"})


def test_tenant_plane_has_no_ceiling():
    """A tenant's own administrator legitimately holds everything on their own stack —
    the ceiling exists to constrain the *provider* issuer, not to re-litigate tenant RBAC."""
    cfg = _cfg(TENANT_ISS, plane=PLANE_TENANT, group_roles={"mcp-admins": "admin"})
    assert cfg.plane == PLANE_TENANT


@pytest.mark.asyncio
async def test_the_provider_ceiling_holds_for_a_legal_mapping(rig):
    """The everyday grant works and stays inside the ceiling."""
    v, _, provider_key = rig
    p = await v.validate(_token(provider_key, iss=PROVIDER_ISS, kid="key-1", groups=["provider-admins"]))
    assert {SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_METRICS_READ} <= p.scopes
    assert SCOPE_TOOLS_CALL not in p.scopes
    assert SCOPE_BACKUP_READ not in p.scopes


@pytest.mark.asyncio
async def test_ceiling_is_reapplied_at_validation_when_the_mapping_drifts_past_startup(rig):
    """The startup check is a claim about one moment; this is the claim about every request.

    **Found by mutation, and it was the fixture-starts-past-the-bug pattern again.** The
    original version of this test used the rig's legal `operator` mapping, whose scopes are
    already inside the ceiling — so the intersection never removed anything, and deleting it
    entirely changed no result. The mutant survived.

    Here the mapping is widened *after* construction, which is exactly the case the
    validation-time check exists for: a config reload, or `ROLE_SCOPES` gaining a scope,
    after the startup guard has already run and passed.
    """
    v, _, provider_key = rig
    cfg = v.for_issuer(PROVIDER_ISS).config
    cfg.group_roles["provider-admins"] = "admin"  # drift past the startup guard

    p = await v.validate(_token(provider_key, iss=PROVIDER_ISS, kid="key-1", groups=["provider-admins"]))
    assert SCOPE_TOOLS_CALL not in p.scopes, "provider issuer reached tool invocation (§5a)"
    assert SCOPE_BACKUP_READ not in p.scopes, "provider issuer reached a credential dump (§5b)"
    assert SCOPE_BACKUP_EXPORT_PORTABLE not in p.scopes
    assert SCOPE_DEVICES_WRITE in p.scopes  # what the ceiling does allow survives


# --- Back-compat: the single-issuer config keeps working ---------------------


def test_legacy_single_issuer_config_still_builds():
    """Existing deployments configure `gateway.oidc.issuer` as a string. That must keep
    working untouched — a security refactor that forces a config migration on every
    existing operator gets deferred, and then nobody gets the isolation."""
    v = build_oidc_validator(
        {
            "gateway": {
                "oidc": {
                    "enabled": True,
                    "issuer": TENANT_ISS,
                    "audience": AUDIENCE,
                    "group_roles": {"mcp-admins": "admin"},
                    "jwks_uri": f"{TENANT_ISS}/jwks",
                }
            },
            "security": {"allow_private_targets": True},
        }
    )
    assert isinstance(v, MultiIssuerValidator)
    assert v.issuers == [TENANT_ISS]
    assert v.for_issuer(TENANT_ISS).config.plane == PLANE_TENANT


def test_multi_issuer_config_builds_both_planes():
    v = build_oidc_validator(
        {
            "gateway": {
                "oidc": {
                    "enabled": True,
                    "issuers": [
                        {
                            "issuer": TENANT_ISS,
                            "audience": AUDIENCE,
                            "plane": PLANE_TENANT,
                            "group_roles": {"mcp-admins": "admin"},
                            "jwks_uri": f"{TENANT_ISS}/jwks",
                        },
                        {
                            "issuer": PROVIDER_ISS,
                            "audience": AUDIENCE,
                            "plane": PLANE_PROVIDER,
                            "group_roles": {"provider-admins": "operator"},
                            "jwks_uri": f"{PROVIDER_ISS}/jwks",
                        },
                    ],
                }
            },
            "security": {"allow_private_targets": True},
        }
    )
    assert v.issuers == [TENANT_ISS, PROVIDER_ISS]


def test_duplicate_issuers_are_refused():
    """Two entries for one issuer means one of them silently never applies — and which
    one wins is an ordering accident."""
    with pytest.raises(ValueError, match="duplicate"):
        MultiIssuerValidator(
            [
                _cfg(TENANT_ISS, plane=PLANE_TENANT, group_roles={"a": "viewer"}),
                _cfg(TENANT_ISS, plane=PLANE_PROVIDER, group_roles={"b": "viewer"}),
            ]
        )
