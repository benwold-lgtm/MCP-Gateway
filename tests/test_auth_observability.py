# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Auth observability and key strength (third-party review items 10 and 11).

Item 10 — the OIDC→static-key fall-through was logged at ``debug``. An IdP/JWKS outage
therefore degraded the whole deployment to break-glass-keys-only with no operator signal,
and someone probing with forged JWTs generated nothing at all. Now a rate-limited WARNING
plus an ``mcp_oidc_validation_failures_total`` counter.

Item 11 — ``build_static_authenticator`` accepted ``MCP_ADMIN_KEY=admin``. A weak
break-glass key is the whole auth story when the IdP is down.
"""

import pytest
from prometheus_client import REGISTRY

from device_mcp_gateway.rbac import Authenticator, build_static_authenticator


def _counter(reason):
    v = REGISTRY.get_sample_value("mcp_oidc_validation_failures_total", {"reason": reason})
    return v or 0.0


# --- item 10: OIDC failures are visible --------------------------------------


@pytest.mark.asyncio
async def test_oidc_failure_increments_the_counter(monkeypatch):
    """An IdP outage must leave a Prometheus trace, not just a debug line."""
    from device_mcp_gateway.oidc import OIDCError
    from device_mcp_gateway.rbac import CompositeAuthenticator

    class _Failing:
        async def validate(self, token):
            raise OIDCError("no JWKS key for kid='abc' (unknown key or IdP unreachable)")

    static = Authenticator({"break-glass-key-that-is-long": _principal()}, True)
    comp = CompositeAuthenticator(static=static, oidc=_Failing())

    before = _counter("jwks_unavailable")
    with pytest.raises(Exception):
        await comp.authenticate_async(_creds(_JWT))
    assert _counter("jwks_unavailable") == before + 1


@pytest.mark.asyncio
async def test_failure_reasons_are_classified_with_bounded_cardinality(monkeypatch):
    """The label must be a small fixed set — the raw exception text would put attacker-
    controlled JWT contents into a Prometheus label and blow up cardinality."""
    from device_mcp_gateway.rbac import _classify_oidc_failure

    assert _classify_oidc_failure("no JWKS key for kid='x' (unknown key or IdP unreachable)") == "jwks_unavailable"
    assert _classify_oidc_failure("JWT validation failed: Signature verification failed") == "invalid_token"
    assert _classify_oidc_failure("JWT validation failed: Signature has expired") == "expired"
    assert _classify_oidc_failure("alg 'HS256' not in allow-list ['RS256']") == "bad_algorithm"
    assert _classify_oidc_failure("something entirely new") == "other"
    # Whatever comes in, the label is always drawn from the fixed set.
    from device_mcp_gateway.rbac import _OIDC_FAILURE_REASONS

    for text in ("", "kid=<script>", "x" * 5000):
        assert _classify_oidc_failure(text) in _OIDC_FAILURE_REASONS


@pytest.mark.asyncio
async def test_first_failure_warns_and_the_flood_is_rate_limited(monkeypatch):
    """A forged-JWT flood must not become a log flood — but it must not be silent either."""
    from device_mcp_gateway.oidc import OIDCError
    from device_mcp_gateway.rbac import CompositeAuthenticator

    class _Failing:
        async def validate(self, token):
            raise OIDCError("JWT validation failed: Signature verification failed")

    warnings = []
    from device_mcp_gateway import rbac as rbac_mod

    monkeypatch.setattr(rbac_mod.logger, "warning", lambda msg, *a, **k: warnings.append(str(msg)))

    comp = CompositeAuthenticator(static=Authenticator({}, False), oidc=_Failing())
    for _ in range(50):
        with pytest.raises(Exception):
            await comp.authenticate_async(_creds(_JWT))

    assert len(warnings) == 1, f"expected one warning, got {len(warnings)}"
    assert "OIDC" in warnings[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message, expect_reachability_advice",
    [
        ("no JWKS key for kid='x' (unknown key or IdP unreachable)", True),
        ("JWT validation failed: Audience doesn't match", False),
        ("JWT validation failed: Signature verification failed", False),
    ],
)
async def test_reachability_advice_only_for_reachability_failures(monkeypatch, message, expect_reachability_advice):
    """ "Your IdP may be unreachable" must not be appended to every failure.

    A wrong audience and a forged signature are the gateway working as designed. Telling
    the operator to go and check IdP connectivity buries the real reason under a wrong one,
    and it is the path someone reads during an incident.
    """
    from device_mcp_gateway.oidc import OIDCError
    from device_mcp_gateway.rbac import CompositeAuthenticator

    class _Failing:
        async def validate(self, token):
            raise OIDCError(message)

    warnings: list[str] = []
    from device_mcp_gateway import rbac as rbac_mod

    monkeypatch.setattr(rbac_mod.logger, "warning", lambda msg, *a, **k: warnings.append(str(msg)))

    comp = CompositeAuthenticator(static=Authenticator({}, False), oidc=_Failing())
    with pytest.raises(Exception):
        await comp.authenticate_async(_creds(_JWT))

    assert warnings, "the failure must still be reported"
    said = "JWKS endpoint is unreachable" in warnings[0]
    assert said is expect_reachability_advice, warnings[0]
    if not expect_reachability_advice:
        assert "refused on its own merits" in warnings[0]


@pytest.mark.asyncio
async def test_suppressed_count_is_reported_on_the_next_warning(monkeypatch):
    """Rate limiting must not hide the scale of the problem."""
    from device_mcp_gateway.oidc import OIDCError
    from device_mcp_gateway.rbac import CompositeAuthenticator
    from device_mcp_gateway import rbac as rbac_mod

    class _Failing:
        async def validate(self, token):
            raise OIDCError("JWT validation failed: Signature verification failed")

    warnings = []
    monkeypatch.setattr(rbac_mod.logger, "warning", lambda msg, *a, **k: warnings.append(str(msg)))

    comp = CompositeAuthenticator(static=Authenticator({}, False), oidc=_Failing())
    for _ in range(10):
        with pytest.raises(Exception):
            await comp.authenticate_async(_creds(_JWT))

    # Force the window open again; the next warning should account for the suppressed ones.
    comp._oidc_warn_last = 0.0
    with pytest.raises(Exception):
        await comp.authenticate_async(_creds(_JWT))

    assert len(warnings) == 2
    assert "9 similar" in warnings[1] or "suppressed" in warnings[1].lower()


@pytest.mark.asyncio
async def test_a_valid_token_neither_warns_nor_counts(monkeypatch):
    from device_mcp_gateway.rbac import CompositeAuthenticator
    from device_mcp_gateway import rbac as rbac_mod

    class _OK:
        async def validate(self, token):
            return _principal()

    warnings = []
    monkeypatch.setattr(rbac_mod.logger, "warning", lambda msg, *a, **k: warnings.append(str(msg)))
    before = _counter("invalid_token")

    comp = CompositeAuthenticator(static=Authenticator({}, False), oidc=_OK())
    assert await comp.authenticate_async(_creds(_JWT)) is not None
    assert warnings == []
    assert _counter("invalid_token") == before


# --- item 11: static key strength --------------------------------------------


def test_weak_admin_key_is_flagged(monkeypatch):
    """The review's example: MCP_ADMIN_KEY=admin was accepted silently."""
    from device_mcp_gateway.rbac import weak_static_keys

    for k in ("MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", "admin")
    weak = weak_static_keys({})
    assert weak, "MCP_ADMIN_KEY=admin must be reported as weak"
    assert any("MCP_ADMIN_KEY" in name for name, _ in weak)
    assert any("guessable" in why for _, why in weak)


@pytest.mark.parametrize("key", ["admin", "password", "changeme", "secret", "test", "mcp"])
def test_common_guessable_keys_are_flagged(monkeypatch, key):
    from device_mcp_gateway.rbac import weak_static_keys

    for k in ("MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", key)
    assert weak_static_keys({}), f"{key!r} should be flagged"


def test_short_key_is_flagged(monkeypatch):
    from device_mcp_gateway.rbac import weak_static_keys

    for k in ("MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", "abc123")
    assert weak_static_keys({})


def test_a_generated_strength_key_passes(monkeypatch):
    """Everything the project itself generates or documents must pass: the LITE bootstrap
    uses secrets.token_urlsafe(24) (32 chars) and the docs use openssl rand -hex 24/32."""
    import secrets

    from device_mcp_gateway.rbac import weak_static_keys

    for k in ("MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY"):
        monkeypatch.delenv(k, raising=False)
    for generated in (secrets.token_urlsafe(24), secrets.token_hex(24), secrets.token_hex(32)):
        monkeypatch.setenv("MCP_ADMIN_KEY", generated)
        assert weak_static_keys({}) == [], f"{generated!r} should be accepted"


def test_weak_key_in_rbac_config_block_is_flagged():
    from device_mcp_gateway.rbac import weak_static_keys

    cfg = {"gateway": {"rbac": [{"name": "ci", "key": "hunter2", "role": "admin"}]}}
    weak = weak_static_keys(cfg)
    assert any("ci" in name for name, _ in weak)


def test_no_keys_configured_is_not_a_weak_key_problem():
    """Auth-disabled is a different finding (F-23) with its own gate — don't double-report."""
    from device_mcp_gateway.rbac import weak_static_keys

    assert weak_static_keys({}) == []


def test_build_static_authenticator_warns_but_still_builds(monkeypatch):
    """Embedded/local dev must keep working — the hard refusal is the distributed gate."""
    from device_mcp_gateway import rbac as rbac_mod

    for k in ("MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", "admin")
    warnings = []
    monkeypatch.setattr(rbac_mod.logger, "warning", lambda msg, *a, **k: warnings.append(str(msg)))

    auth = build_static_authenticator({})
    assert auth.enabled
    assert auth.match("admin") is not None  # still usable in dev
    assert any("weak" in w.lower() for w in warnings)


def test_distributed_mode_refuses_a_weak_key(monkeypatch):
    """Same fail-closed-in-production shape as the F-23/F-24 gates."""
    from device_mcp_gateway.main import create_app

    for k in ("MCP_GATEWAY_API_KEY", "MCP_VIEWER_KEY", "MCP_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", "admin")
    cfg = {
        "registry": {"mode": "distributed"},
        "gateway": {"allow_plaintext_credentials": True},
        "redis": {"allow_insecure": True},
    }
    with pytest.raises(RuntimeError, match="weak"):
        create_app(override_config=cfg)


def test_distributed_mode_weak_key_override_starts(monkeypatch):
    from device_mcp_gateway.main import create_app

    for k in ("MCP_GATEWAY_API_KEY", "MCP_VIEWER_KEY", "MCP_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", "admin")
    cfg = {
        "registry": {"mode": "distributed"},
        "gateway": {"allow_plaintext_credentials": True, "allow_weak_keys": True},
        "redis": {"allow_insecure": True},
    }
    app = create_app(override_config=cfg)  # must not raise
    assert app.state.mode == "distributed"


def test_distributed_mode_with_a_strong_key_starts(monkeypatch):
    import secrets

    from device_mcp_gateway.main import create_app

    for k in ("MCP_GATEWAY_API_KEY", "MCP_VIEWER_KEY", "MCP_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MCP_ADMIN_KEY", secrets.token_urlsafe(24))
    cfg = {
        "registry": {"mode": "distributed"},
        "gateway": {"allow_plaintext_credentials": True},
        "redis": {"allow_insecure": True},
    }
    app = create_app(override_config=cfg)  # must not raise
    assert app.state.mode == "distributed"


# --- helpers -----------------------------------------------------------------

# A syntactically JWT-shaped token so the composite routes it to the OIDC validator.
_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"


def _principal():
    from device_mcp_gateway.rbac import Principal, scopes_for_role

    return Principal(subject="key:test", scopes=scopes_for_role("admin"), auth_method="api_key")


def _creds(token):
    from fastapi.security import HTTPAuthorizationCredentials

    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
