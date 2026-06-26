# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
OIDC JWT validation for inbound gateway auth (ADR-0007, F-15/F-30).

This is the federated half of the composite authenticator: a request that presents a
JWT is validated against the IdP's published signing keys (JWKS) and mapped to a
``Principal`` through the gateway-owned ``group_roles`` table. Static API keys remain
the break-glass path and are handled by ``rbac.Authenticator``; this module never
touches them.

Security requirements implemented here come straight from the identity threat-model
addendum (docs/threat-model-identity.md):

  * **TM-I-08** — signature checked against JWKS; ``iss``/``aud``/``exp``/``nbf``
    enforced with bounded clock skew; an **asymmetric algorithm allow-list** (``alg``
    from the token header must be in the configured set; ``none`` and symmetric ``HS*``
    are rejected at config time); ``kid`` matched to a known key — a key embedded in
    the token is never trusted.
  * **TM-I-09** — JWKS is fetched only from the issuer over TLS, cached with a bounded
    TTL, and on a ``kid`` miss refreshed at most once per ``jwks_min_refresh_interval``
    (rate-limited) so an unknown-``kid`` flood cannot become a fetch-amplification DoS.
  * **TM-I-10** — the issuer / JWKS URL is run through the egress URL policy (it is
    operator config, not request input, but is still validated before any fetch).
  * **TM-I-12** — JWKS is served from cache through an IdP outage; validation fails
    **closed** (the JWT is rejected) while static break-glass keys keep working.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx
import jwt
from loguru import logger

from device_mcp_gateway.rbac import Principal, scopes_for_role
from device_mcp_gateway.security.url_policy import UrlPolicyError, validate_target_url

# Asymmetric signature algorithms we will accept. Symmetric (HS*) and ``none`` are
# deliberately excluded — a shared-secret or unsigned token has no place validating a
# federated identity (TM-I-08).
ASYMMETRIC_ALGORITHMS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
)

AUTH_METHOD_OIDC = "oidc"


class OIDCError(Exception):
    """A JWT could not be validated. The composite authenticator treats this as a
    fall-through (try static keys, else 401) — never as a server error."""


@dataclass
class OIDCConfig:
    issuer: str
    audience: str
    group_roles: dict[str, str]
    jwks_uri: Optional[str] = None
    groups_claim: str = "groups"
    subject_claim: str = "sub"
    algorithms: tuple[str, ...] = ("RS256",)
    leeway: int = 60  # clock-skew tolerance, seconds
    jwks_cache_ttl: int = 600  # how long a fetched key set is trusted, seconds
    jwks_min_refresh_interval: int = 30  # rate-limit on kid-miss refetch, seconds
    http_timeout: float = 5.0
    allow_private_targets: bool = False

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("gateway.oidc.issuer is required when OIDC is enabled")
        if not self.audience:
            raise ValueError("gateway.oidc.audience is required when OIDC is enabled")
        bad = [a for a in self.algorithms if a not in ASYMMETRIC_ALGORITHMS]
        if bad or not self.algorithms:
            raise ValueError(
                f"gateway.oidc.algorithms must be a non-empty subset of asymmetric algorithms "
                f"{sorted(ASYMMETRIC_ALGORITHMS)}; rejected {bad or 'empty'} (HS*/none are not allowed)"
            )
        # Validate every configured group→role now so a typo fails fast at startup, not
        # on the first login. Roles must be known scope bundles.
        for grp, role in self.group_roles.items():
            scopes_for_role(role)  # raises ValueError on unknown role
        # The issuer (and an explicit JWKS URI) are operator config but still fetched
        # server-side — run them through the same egress policy as device targets (TM-I-10).
        self._check_url(self.issuer, "gateway.oidc.issuer")
        if self.jwks_uri:
            self._check_url(self.jwks_uri, "gateway.oidc.jwks_uri")

    def _check_url(self, url: str, field_name: str) -> None:
        try:
            validate_target_url(url, allow_private=self.allow_private_targets)
        except UrlPolicyError as exc:
            raise ValueError(
                f"{field_name} rejected by egress policy: {exc}. For an on-prem IdP on a "
                f"private network set security.allow_private_targets: true."
            )


class JWKSCache:
    """Holds the issuer's signing keys, fetched lazily and refreshed within bounds.

    Network fetches go through ``_fetch`` so tests can seed keys without I/O. The cache
    is intentionally simple: a dict keyed by ``kid``, a fetch timestamp for TTL, and a
    separate timestamp to rate-limit kid-miss refetches (TM-I-09).
    """

    def __init__(self, cfg: OIDCConfig) -> None:
        self._cfg = cfg
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._last_refresh_attempt: float = 0.0
        self._discovered_jwks_uri: Optional[str] = cfg.jwks_uri

    def seed(self, jwks: dict[str, Any]) -> None:
        """Install a key set directly (startup warm-up / tests). Marks the cache fresh."""
        self._install(jwks)

    def _install(self, jwks: dict[str, Any]) -> None:
        self._keys = {k["kid"]: k for k in jwks.get("keys", []) if k.get("kid")}
        self._fetched_at = time.monotonic()

    @property
    def _fresh(self) -> bool:
        return bool(self._keys) and (time.monotonic() - self._fetched_at) < self._cfg.jwks_cache_ttl

    async def get_key(self, kid: str) -> dict[str, Any]:
        """Return the JWK for ``kid``, fetching/refreshing within the rate limit.

        Raises ``OIDCError`` if the key cannot be resolved (unknown kid, or the IdP is
        unreachable and nothing is cached). The caller falls through to static keys.
        """
        if self._fresh and kid in self._keys:
            return self._keys[kid]
        # Either the cache is stale or this kid is unknown. Try a refresh, but only if we
        # have not refreshed very recently — an unknown-kid flood must not become a fetch
        # flood against the IdP (TM-I-09).
        now = time.monotonic()
        if (now - self._last_refresh_attempt) >= self._cfg.jwks_min_refresh_interval:
            self._last_refresh_attempt = now
            try:
                await self._refresh()
            except Exception as exc:  # network, TLS, JSON, policy — all fall through
                logger.warning(f"OIDC JWKS refresh failed (serving from cache if present): {exc}")
        if kid in self._keys:
            return self._keys[kid]
        raise OIDCError(f"no JWKS key for kid={kid!r} (unknown key or IdP unreachable)")

    async def _refresh(self) -> None:
        uri = await self._resolve_jwks_uri()
        # The JWKS URI may have been discovered at runtime; validate it before fetching.
        validate_target_url(uri, allow_private=self._cfg.allow_private_targets)
        async with httpx.AsyncClient(timeout=self._cfg.http_timeout) as client:
            resp = await client.get(uri)
            resp.raise_for_status()
            self._install(resp.json())
        logger.info(f"OIDC JWKS refreshed from {uri} ({len(self._keys)} key(s))")

    async def _resolve_jwks_uri(self) -> str:
        if self._discovered_jwks_uri:
            return self._discovered_jwks_uri
        # OIDC discovery: <issuer>/.well-known/openid-configuration → jwks_uri.
        disco = self._cfg.issuer.rstrip("/") + "/.well-known/openid-configuration"
        validate_target_url(disco, allow_private=self._cfg.allow_private_targets)
        async with httpx.AsyncClient(timeout=self._cfg.http_timeout) as client:
            resp = await client.get(disco)
            resp.raise_for_status()
            uri = resp.json().get("jwks_uri")
        if not uri:
            raise OIDCError("OIDC discovery document has no jwks_uri")
        self._discovered_jwks_uri = uri
        return uri


class OIDCValidator:
    """Validates a JWT and maps it to a Principal. Stateless apart from the JWKS cache."""

    def __init__(self, cfg: OIDCConfig, jwks: Optional[JWKSCache] = None) -> None:
        self._cfg = cfg
        self._jwks = jwks or JWKSCache(cfg)

    @property
    def jwks(self) -> JWKSCache:
        return self._jwks

    async def validate(self, token: str) -> Principal:
        """Return the Principal for a valid JWT, or raise ``OIDCError``."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OIDCError(f"malformed JWT header: {exc}")

        alg = header.get("alg")
        if alg not in self._cfg.algorithms:
            # Algorithm-confusion / 'none' / unexpected alg — reject before any crypto.
            raise OIDCError(f"alg {alg!r} not in allow-list {list(self._cfg.algorithms)}")
        kid = header.get("kid")
        if not kid:
            raise OIDCError("JWT header has no kid")

        jwk = await self._jwks.get_key(kid)
        try:
            signing_key = jwt.PyJWK.from_dict(jwk).key
        except jwt.PyJWTError as exc:
            raise OIDCError(f"unusable JWKS key for kid={kid!r}: {exc}")

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=list(self._cfg.algorithms),
                audience=self._cfg.audience,
                issuer=self._cfg.issuer,
                leeway=self._cfg.leeway,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise OIDCError(f"JWT validation failed: {exc}")

        return self._principal_from_claims(claims)

    def _principal_from_claims(self, claims: dict[str, Any]) -> Principal:
        subject = claims.get(self._cfg.subject_claim) or claims.get("sub")
        if not subject:
            raise OIDCError(f"JWT missing subject claim {self._cfg.subject_claim!r}")

        raw_groups = claims.get(self._cfg.groups_claim, [])
        if isinstance(raw_groups, str):  # some IdPs emit a single group as a bare string
            raw_groups = [raw_groups]
        groups = [g for g in raw_groups if isinstance(g, str)]

        # The gateway owns group→role→scope; the IdP only asserts membership (ADR-0007
        # §Decision 3). A user in several mapped groups gets the union of their scopes.
        scopes: set[str] = set()
        mapped_any = False
        for grp in groups:
            role = self._cfg.group_roles.get(grp)
            if role is None:
                continue
            mapped_any = True
            scopes |= scopes_for_role(role)
        if not mapped_any:
            # Authenticated but no mapped group → an authenticated principal with no
            # scopes. Every route guard then 403s, and the audit shows *who* was denied
            # (better than a blanket 401 that hides the identity).
            logger.info(f"OIDC subject {subject!r} authenticated but no group maps to a role (groups={groups})")

        return Principal(subject=f"oidc:{subject}", scopes=frozenset(scopes), auth_method=AUTH_METHOD_OIDC)


def build_oidc_validator(cfg: dict) -> Optional[OIDCValidator]:
    """Construct an ``OIDCValidator`` from config, or ``None`` if OIDC is not enabled.

    Reads ``gateway.oidc`` (inbound auth lives under ``gateway.*``, alongside
    ``api_key`` / ``rbac``). Resolution failures raise ``ValueError`` so a misconfigured
    IdP fails fast at startup rather than on the first login.
    """
    from device_mcp_gateway.security.url_policy import resolve_allow_private

    oidc_cfg = (cfg.get("gateway", {}) or {}).get("oidc", {}) or {}
    if not oidc_cfg.get("enabled", False):
        return None

    algorithms = tuple(oidc_cfg.get("algorithms") or ("RS256",))
    config = OIDCConfig(
        issuer=oidc_cfg.get("issuer", ""),
        audience=oidc_cfg.get("audience", ""),
        group_roles=dict(oidc_cfg.get("group_roles", {}) or {}),
        jwks_uri=oidc_cfg.get("jwks_uri"),
        groups_claim=oidc_cfg.get("groups_claim", "groups"),
        subject_claim=oidc_cfg.get("subject_claim", "sub"),
        algorithms=algorithms,
        leeway=int(oidc_cfg.get("leeway", 60)),
        jwks_cache_ttl=int(oidc_cfg.get("jwks_cache_ttl", 600)),
        jwks_min_refresh_interval=int(oidc_cfg.get("jwks_min_refresh_interval", 30)),
        http_timeout=float(oidc_cfg.get("http_timeout", 5.0)),
        allow_private_targets=resolve_allow_private(cfg),
    )
    logger.info(
        f"OIDC inbound auth enabled: issuer={config.issuer} audience={config.audience} "
        f"algs={list(config.algorithms)} groups_claim={config.groups_claim} "
        f"roles={sorted(set(config.group_roles.values()))}"
    )
    return OIDCValidator(config)
