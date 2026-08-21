# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""TM-I-05 — the gateway pins the OIDC discovery document to the configured issuer.

The gap these cover: ``_resolve_jwks_uri`` took ``jwks_uri`` straight out of the discovery
document and cached it for the process lifetime, with nothing checking that the document
declared the issuer it was fetched from. Pinning ``iss``/``aud`` at ``jwt.decode`` does not
close that — an attacker who supplies the *keys* also chooses the claims. This is the same
bug the BFF had (``bff/tests/test_oidc_issuer_pinning.py``), on the side that actually
enforces authorization.

These drive the real HTTP path rather than monkeypatching ``_refresh``, because the defect
lived entirely in the code between the response and the cache.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from device_mcp_gateway import oidc as oidc_mod
from device_mcp_gateway.oidc import JWKSCache, OIDCConfig, OIDCError, OIDCValidator

ISSUER = "https://idp.example.com"
AUDIENCE = "device-mcp-gateway"


def _config(**overrides) -> OIDCConfig:
    params = dict(
        issuer=ISSUER,
        audience=AUDIENCE,
        group_roles={"mcp-admins": "admin"},
        jwks_uri=None,  # force discovery — an explicit URI short-circuits it entirely
        allow_private_targets=True,  # skip DNS resolution → fully offline
    )
    params.update(overrides)
    return OIDCConfig(**params)


class _Resp:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def _serve(*documents: dict, calls: list | None = None):
    """Patch the guarded client to return ``documents`` in order, recording the URLs."""
    queue = list(documents)

    class _Client:
        async def get(self, url):
            if calls is not None:
                calls.append(url)
            return _Resp(queue.pop(0) if len(queue) > 1 else queue[0])

    @asynccontextmanager
    async def _build(**_kwargs):
        yield _Client()

    return _build


@pytest.mark.asyncio
async def test_declared_issuer_must_match_config(monkeypatch):
    monkeypatch.setattr(
        oidc_mod, "build_guarded_client", _serve({"issuer": "https://evil.test", "jwks_uri": "https://evil.test/jwks"})
    )
    cache = JWKSCache(_config())
    with pytest.raises(OIDCError, match="discovery issuer mismatch"):
        await cache._resolve_jwks_uri()


@pytest.mark.asyncio
async def test_a_refused_document_is_not_cached(monkeypatch):
    """The poisoning half: one spoof must not stick for the process lifetime."""
    spoof = {"issuer": "https://evil.test", "jwks_uri": "https://evil.test/jwks"}
    good = {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"}
    cache = JWKSCache(_config())

    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(spoof))
    with pytest.raises(OIDCError):
        await cache._resolve_jwks_uri()
    assert cache._discovered_jwks_uri is None

    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(good))
    assert await cache._resolve_jwks_uri() == f"{ISSUER}/jwks"


@pytest.mark.asyncio
async def test_absent_issuer_is_refused(monkeypatch):
    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve({"jwks_uri": f"{ISSUER}/jwks"}))
    cache = JWKSCache(_config())
    with pytest.raises(OIDCError, match="discovery issuer mismatch"):
        await cache._resolve_jwks_uri()


@pytest.mark.asyncio
async def test_prefix_collision_is_refused(monkeypatch):
    """`https://idp.example.com.evil.test` starts with the configured issuer as a string."""
    doc = {"issuer": f"{ISSUER}.evil.test", "jwks_uri": f"{ISSUER}.evil.test/jwks"}
    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(doc))
    cache = JWKSCache(_config())
    with pytest.raises(OIDCError, match="discovery issuer mismatch"):
        await cache._resolve_jwks_uri()


@pytest.mark.asyncio
async def test_trailing_slash_is_not_a_mismatch(monkeypatch):
    """A config-style difference, not a different issuer — must not fail closed."""
    doc = {"issuer": ISSUER + "/", "jwks_uri": f"{ISSUER}/jwks"}
    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(doc))
    cache = JWKSCache(_config())
    assert await cache._resolve_jwks_uri() == f"{ISSUER}/jwks"


@pytest.mark.asyncio
async def test_discovered_plaintext_jwks_uri_is_refused(monkeypatch):
    """A matching issuer must not be able to downgrade the key fetch to plaintext."""
    doc = {"issuer": ISSUER, "jwks_uri": "http://idp.example.com/jwks"}
    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(doc))
    cache = JWKSCache(_config())
    with pytest.raises(OIDCError, match="plaintext http"):
        await cache._resolve_jwks_uri()
    assert cache._discovered_jwks_uri is None


@pytest.mark.asyncio
async def test_discovered_plaintext_jwks_uri_allowed_when_flag_set(monkeypatch):
    """The lab escape hatch is the same one flag, not a second bypass."""
    doc = {"issuer": ISSUER, "jwks_uri": "http://idp.example.com/jwks"}
    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(doc))
    cache = JWKSCache(_config(allow_plaintext_idp=True))
    assert await cache._resolve_jwks_uri() == "http://idp.example.com/jwks"


@pytest.mark.asyncio
async def test_a_token_signed_by_the_spoofed_jwks_is_refused(monkeypatch):
    """End to end: the attacker mints iss/aud to match, and still gets nothing.

    This is the property the fix exists for. Pre-fix, the attacker's key would be installed
    from their own jwks_uri and this signature would verify.
    """
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(attacker.public_key()))
    jwk["kid"] = "attacker-key"
    jwk["alg"] = "RS256"

    spoof = {"issuer": "https://evil.test", "jwks_uri": "https://evil.test/jwks"}
    monkeypatch.setattr(oidc_mod, "build_guarded_client", _serve(spoof, {"keys": [jwk]}))

    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "attacker", "groups": ["mcp-admins"], "exp": 9999999999},
        attacker,
        algorithm="RS256",
        headers={"kid": "attacker-key"},
    )
    validator = OIDCValidator(_config())
    with pytest.raises(OIDCError):
        await validator.validate(token)
