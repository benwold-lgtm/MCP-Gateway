# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0007 — OIDC JWT validation + the composite (OIDC → static-key → 401) authenticator.

Tokens are signed with a locally-generated RSA key and the matching public JWK is
seeded into the JWKS cache, so the whole suite runs offline (no IdP, no network). The
requirements exercised map to docs/threat-model-identity.md (TM-I-08/09/12).
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.security import HTTPAuthorizationCredentials

from device_mcp_gateway.oidc import OIDCConfig, OIDCError, OIDCValidator
from device_mcp_gateway.rbac import (
    ALL_SCOPES,
    ROLE_SCOPES,
    SCOPE_METRICS_READ,
    Authenticator,
    CompositeAuthenticator,
    Principal,
    build_authenticator,
)

ISSUER = "https://idp.example.com"
AUDIENCE = "device-mcp-gateway"
KID = "test-key-1"


def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(priv: rsa.RSAPrivateKey, kid: str = KID) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    return jwk


def _config(**overrides) -> OIDCConfig:
    params = dict(
        issuer=ISSUER,
        audience=AUDIENCE,
        group_roles={"mcp-admins": "admin", "mcp-viewers": "viewer", "mcp-auditors": "auditor"},
        jwks_uri=f"{ISSUER}/jwks",
        allow_private_targets=True,  # skip DNS resolution → fully offline
    )
    params.update(overrides)
    return OIDCConfig(**params)


def _validator(priv: rsa.RSAPrivateKey, **cfg_overrides) -> OIDCValidator:
    v = OIDCValidator(_config(**cfg_overrides))
    v.jwks.seed({"keys": [_jwk(priv)]})
    return v


def _token(priv: rsa.RSAPrivateKey, *, kid: str = KID, alg: str = "RS256", **claim_overrides) -> str:
    claims = {
        "sub": "alice",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "groups": ["mcp-admins"],
    }
    claims.update(claim_overrides)
    return jwt.encode(claims, priv, algorithm=alg, headers={"kid": kid})


def _bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


# --- OIDCConfig validation (fail-fast at startup) -----------------------------


def test_config_rejects_symmetric_and_none_algs():
    for bad in ("HS256", "none"):
        with pytest.raises(ValueError):
            _config(algorithms=(bad,))


def test_config_rejects_empty_algorithms():
    with pytest.raises(ValueError):
        _config(algorithms=())


def test_config_rejects_unknown_group_role():
    with pytest.raises(ValueError):
        _config(group_roles={"mcp-admins": "superuser"})


def test_config_requires_issuer_and_audience():
    with pytest.raises(ValueError):
        _config(issuer="")
    with pytest.raises(ValueError):
        _config(audience="")


# --- Happy path + scope mapping ----------------------------------------------


@pytest.mark.asyncio
async def test_valid_token_maps_groups_to_scopes():
    priv = _keypair()
    v = _validator(priv)
    p = await v.validate(_token(priv, groups=["mcp-admins"]))
    assert p.subject == "oidc:alice"
    assert p.auth_method == "oidc"
    assert p.scopes == ALL_SCOPES


@pytest.mark.asyncio
async def test_multiple_groups_union_scopes():
    priv = _keypair()
    v = _validator(priv)
    p = await v.validate(_token(priv, groups=["mcp-viewers", "mcp-auditors"]))
    # viewer ∪ auditor → still just read+metrics (auditor ⊂ viewer here), but exercises union.
    assert p.scopes == ROLE_SCOPES["viewer"] | ROLE_SCOPES["auditor"]


@pytest.mark.asyncio
async def test_string_groups_claim_is_accepted():
    priv = _keypair()
    v = _validator(priv)
    p = await v.validate(_token(priv, groups="mcp-viewers"))
    assert p.scopes == ROLE_SCOPES["viewer"]


@pytest.mark.asyncio
async def test_unmapped_groups_yield_authenticated_but_no_scopes():
    priv = _keypair()
    v = _validator(priv)
    p = await v.validate(_token(priv, groups=["some-other-group"]))
    assert p.subject == "oidc:alice"
    assert p.scopes == frozenset()  # authenticated, unauthorized → routes 403


# --- Rejections (TM-I-08) -----------------------------------------------------


@pytest.mark.asyncio
async def test_wrong_audience_rejected():
    priv = _keypair()
    v = _validator(priv)
    with pytest.raises(OIDCError):
        await v.validate(_token(priv, aud="someone-else"))


@pytest.mark.asyncio
async def test_wrong_issuer_rejected():
    priv = _keypair()
    v = _validator(priv)
    with pytest.raises(OIDCError):
        await v.validate(_token(priv, iss="https://evil.example.com"))


@pytest.mark.asyncio
async def test_expired_token_rejected():
    priv = _keypair()
    v = _validator(priv)
    # Expired well beyond the default 60s clock-skew leeway.
    with pytest.raises(OIDCError):
        await v.validate(_token(priv, exp=int(time.time()) - 120))


@pytest.mark.asyncio
async def test_alg_not_in_allowlist_rejected():
    # Validator only allows RS256; a token signed RS512 must be refused even though RS512
    # is asymmetric — the per-validator allow-list is the contract.
    priv = _keypair()
    v = _validator(priv, algorithms=("RS256",))
    with pytest.raises(OIDCError):
        await v.validate(_token(priv, alg="RS512"))


@pytest.mark.asyncio
async def test_signature_from_unknown_key_rejected():
    priv = _keypair()
    attacker = _keypair()
    v = _validator(priv)  # seeds only priv's public key
    # Signed by the attacker's key but claims the known kid → no matching/validating key.
    with pytest.raises(OIDCError):
        await v.validate(_token(attacker, kid=KID))


@pytest.mark.asyncio
async def test_unknown_kid_rejected_without_network():
    priv = _keypair()
    v = _validator(priv)
    with pytest.raises(OIDCError):
        await v.validate(_token(priv, kid="rotated-away"))


@pytest.mark.asyncio
async def test_missing_subject_rejected():
    priv = _keypair()
    v = _validator(priv)
    tok = _token(priv)
    # Re-sign with sub removed.
    tok = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 300, "groups": ["mcp-admins"]},
        priv,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(OIDCError):
        await v.validate(tok)


# --- JWKS cache: TTL + rate-limited kid-miss refresh (TM-I-09) -----------------


@pytest.mark.asyncio
async def test_kid_miss_refresh_is_rate_limited(monkeypatch):
    priv = _keypair()
    v = _validator(priv)
    calls = {"n": 0}

    async def _fake_refresh():
        calls["n"] += 1  # pretend the IdP returned nothing new

    monkeypatch.setattr(v.jwks, "_refresh", _fake_refresh)
    # First unknown-kid lookup attempts a refresh; immediate retries must NOT (rate limit).
    with pytest.raises(OIDCError):
        await v.jwks.get_key("missing")
    with pytest.raises(OIDCError):
        await v.jwks.get_key("missing")
    assert calls["n"] == 1, "kid-miss refresh should be rate-limited, not per-request"


@pytest.mark.asyncio
async def test_stale_cache_triggers_refresh(monkeypatch):
    priv = _keypair()
    v = _validator(priv, jwks_cache_ttl=0)  # always stale
    refreshed = {"n": 0}
    orig = _jwk(priv)

    async def _fake_refresh():
        refreshed["n"] += 1
        v.jwks.seed({"keys": [orig]})

    monkeypatch.setattr(v.jwks, "_refresh", _fake_refresh)
    # Even though the kid is present, a stale cache forces a refresh attempt.
    await v.jwks.get_key(KID)
    assert refreshed["n"] == 1


# --- CompositeAuthenticator routing ------------------------------------------


def _composite(priv, *, static_keys=None) -> CompositeAuthenticator:
    static = Authenticator(static_keys or {}, enabled=bool(static_keys))
    v = OIDCValidator(_config())
    v.jwks.seed({"keys": [_jwk(priv)]})
    return CompositeAuthenticator(static=static, oidc=v)


@pytest.mark.asyncio
async def test_composite_routes_jwt_to_oidc():
    priv = _keypair()
    comp = _composite(priv, static_keys={"break-glass": Principal("key:admin", ALL_SCOPES, "api_key")})
    p = await comp.authenticate_async(_bearer(_token(priv)))
    assert p.auth_method == "oidc" and p.subject == "oidc:alice"


@pytest.mark.asyncio
async def test_composite_routes_opaque_token_to_static_key():
    priv = _keypair()
    admin = Principal("key:admin", ALL_SCOPES, "api_key")
    comp = _composite(priv, static_keys={"break-glass": admin})
    p = await comp.authenticate_async(_bearer("break-glass"))
    assert p is admin  # break-glass key works regardless of OIDC


@pytest.mark.asyncio
async def test_composite_invalid_jwt_falls_through_then_401():
    priv = _keypair()
    comp = _composite(priv, static_keys={"break-glass": Principal("key:admin", ALL_SCOPES, "api_key")})
    # A JWT-shaped token signed by an unknown key: OIDC rejects → static miss → 401.
    bad = _token(_keypair(), kid="nope")
    with pytest.raises(Exception) as exc:
        await comp.authenticate_async(_bearer(bad))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_composite_no_token_is_401():
    priv = _keypair()
    comp = _composite(priv, static_keys={"k": Principal("key:admin", ALL_SCOPES, "api_key")})
    with pytest.raises(Exception) as exc:
        await comp.authenticate_async(None)
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_composite_idp_down_jwt_fails_but_breakglass_key_works():
    # Simulate the IdP being unreachable: empty JWKS, no key for any kid. A JWT is
    # rejected (fail closed), but the static break-glass key still authenticates (TM-I-12).
    priv = _keypair()
    static = Authenticator({"break-glass": Principal("key:admin", ALL_SCOPES, "api_key")}, enabled=True)
    v = OIDCValidator(_config())  # JWKS never seeded → no keys
    comp = CompositeAuthenticator(static=static, oidc=v)

    with pytest.raises(Exception) as exc:
        await comp.authenticate_async(_bearer(_token(priv)))
    assert getattr(exc.value, "status_code", None) == 401

    p = await comp.authenticate_async(_bearer("break-glass"))
    assert p.scopes == ALL_SCOPES


# --- build_authenticator wiring ----------------------------------------------


def test_build_returns_plain_authenticator_without_oidc(monkeypatch):
    for k in ("MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY"):
        monkeypatch.delenv(k, raising=False)
    auth = build_authenticator({"gateway": {"api_key": "tok"}})
    assert isinstance(auth, Authenticator)


def test_build_returns_composite_with_oidc(monkeypatch):
    monkeypatch.setenv("MCP_ADMIN_KEY", "break-glass")
    cfg = {
        "gateway": {
            "oidc": {
                "enabled": True,
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "jwks_uri": f"{ISSUER}/jwks",
                "group_roles": {"mcp-admins": "admin"},
            }
        },
        "security": {"allow_private_targets": True},
    }
    auth = build_authenticator(cfg)
    assert isinstance(auth, CompositeAuthenticator)
    assert auth.enabled
    assert auth.static.match("break-glass") is not None


def test_new_seed_roles_present():
    assert ROLE_SCOPES["operator"] == frozenset({"devices:read", "devices:write", "metrics:read"})
    assert ROLE_SCOPES["auditor"] == frozenset({SCOPE_METRICS_READ})
    assert ROLE_SCOPES["caller"] == frozenset({"devices:read", "tools:call"})
