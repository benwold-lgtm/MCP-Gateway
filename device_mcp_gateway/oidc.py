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

import jwt
from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.grants import (
    GRANT_CLAIM_DEFAULT,
    ElevatedGrant,
    GrantConsumptionStore,
    GrantError,
    verify_grant,
)
from device_mcp_gateway.rbac import (
    SCOPE_DEVICES_READ,
    SCOPE_DEVICES_WRITE,
    SCOPE_METRICS_READ,
    Principal,
    scopes_for_role,
)
from device_mcp_gateway.security.url_policy import (
    UrlPolicyError,
    build_guarded_client,
    validate_target_url,
)

# --- Planes (ADR-0013 §6a) ---------------------------------------------------
#
# An issuer is not just a key source; it identifies which *population* a token comes from,
# and that has to bind the eligible scope set **server-side**. The BFF fixes the plane at
# login (§3), but that is a session-flow guarantee: once a provider-plane token is minted it
# can be replayed straight at a tenant gateway with the BFF nowhere in the path.

PLANE_TENANT = "tenant"
PLANE_PROVIDER = "provider"

# The maximum scope set reachable from an issuer on each plane. ``None`` means no ceiling.
#
# Tenant: none. A tenant's own administrator legitimately holds everything on their own
# stack — the ceiling exists to constrain the provider issuer, not to re-litigate tenant RBAC.
#
# Provider: the §5a everyday-debugging carve-out. Deliberately excludes:
#   * ``tools:call`` — tool invocation is the most consequential thing the gateway does, and
#     a support engineer debugging a device's configuration should not carry standing
#     authority to actuate the customer's physical hardware (§5a).
#   * every ``backup:*`` scope — the provider holds ``MCP_SECRET_KEY``, so for them a
#     ciphertext archive and a portable one are equally a credential dump, and ADR-0011's
#     ciphertext/portable safety argument carries none of its force here (§5b).
#
# The two elevated grants (`provider:invoke`, `provider:credentials`) are BFF scopes
# exercised as named, time-boxed, individually audited acts — they are not reached by
# widening this ceiling. They reach a tenant gateway as a verifiable claim on the token
# which raises this ceiling for one request; see `device_mcp_gateway/grants.py` and
# ADR-0013 §11.
PLANE_SCOPE_CEILING: dict[str, Optional[frozenset[str]]] = {
    PLANE_TENANT: None,
    PLANE_PROVIDER: frozenset({SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_METRICS_READ}),
}

# Bound the installed JWKS key set (TM-I-09). A spoofed/oversized JWKS response must
# not be able to install an unbounded number of keys (memory / lookup cost). Real IdPs
# publish a handful of signing keys; 50 is comfortably above any legitimate rotation set.
_MAX_JWKS_KEYS = 50

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
    # Which population this issuer speaks for, and therefore its scope ceiling (§6a).
    # Defaults to tenant so an existing single-issuer deployment is unchanged.
    plane: str = PLANE_TENANT
    # This gateway's own tenant identity — one gateway, one tenant (ADR-0004). Knowing its
    # own name is not knowing that other tenants exist; it is what lets it check that a
    # grant claim names *it* rather than the estate (§11a). Required for a provider-plane
    # issuer, meaningless for a tenant-plane one, which honours no grants.
    tenant_id: Optional[str] = None
    # The authentication context that counts as a step-up for this issuer, and the name of
    # the custom claim carrying a grant. With no step_up_acr configured, elevated grants are
    # refused: an unverifiable step-up is not a satisfied one (§11b).
    step_up_acr: tuple[str, ...] = ()
    grant_claim: str = GRANT_CLAIM_DEFAULT
    jwks_uri: Optional[str] = None
    groups_claim: str = "groups"
    subject_claim: str = "sub"
    algorithms: tuple[str, ...] = ("RS256",)
    leeway: int = 60  # clock-skew tolerance, seconds
    jwks_cache_ttl: int = 600  # how long a fetched key set is trusted, seconds
    jwks_min_refresh_interval: int = 30  # rate-limit on kid-miss refetch, seconds
    http_timeout: float = 5.0
    allow_private_targets: bool = False
    allowed_target_ports: set[int] | None = None

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
        if self.plane not in PLANE_SCOPE_CEILING:
            raise ValueError(f"gateway.oidc plane must be one of {sorted(PLANE_SCOPE_CEILING)}; got {self.plane!r}")
        if self.plane == PLANE_PROVIDER and not self.tenant_id:
            # Fail fast rather than on the first elevation. A provider-plane issuer whose
            # gateway has no tenant identity can never honour a grant, and finding that out
            # during an incident — the only time an elevation is wanted — is the worst
            # possible moment. Tenant-plane issuers are unaffected, so no existing
            # single-issuer deployment is forced through a config change.
            raise ValueError(
                f"gateway.oidc issuer {self.issuer!r} is on the provider plane, so gateway.tenant_id must "
                f"be set: an elevated grant names exactly one tenant and this gateway has to know whether "
                f"that is itself (ADR-0013 §11a)."
            )
        # Validate every configured group→role now so a typo fails fast at startup, not
        # on the first login. Roles must be known scope bundles.
        ceiling = PLANE_SCOPE_CEILING[self.plane]
        for grp, role in self.group_roles.items():
            granted = scopes_for_role(role)  # raises ValueError on unknown role
            if ceiling is None:
                continue
            # Refuse the mapping outright rather than silently trimming it. A config that
            # says "provider-admins are gateway admins" is a misunderstanding of §5a, and
            # quietly granting a narrower set would leave the operator believing something
            # false about their own deployment.
            excess = granted - ceiling
            if excess:
                raise ValueError(
                    f"gateway.oidc issuer {self.issuer!r} is on the {self.plane!r} plane, so group "
                    f"{grp!r} cannot map to role {role!r}: that role grants {sorted(excess)}, which is "
                    f"outside the {self.plane} ceiling {sorted(ceiling)} (ADR-0013 §5a/§5b). Tool "
                    f"invocation and credential-bearing reads are elevated, individually audited "
                    f"grants — they are not reached by widening a role mapping."
                )
        # The issuer (and an explicit JWKS URI) are operator config but still fetched
        # server-side — run them through the same egress policy as device targets (TM-I-10).
        self._check_url(self.issuer, "gateway.oidc.issuer")
        if self.jwks_uri:
            self._check_url(self.jwks_uri, "gateway.oidc.jwks_uri")

    def _check_url(self, url: str, field_name: str) -> None:
        try:
            validate_target_url(url, allow_private=self.allow_private_targets, allowed_ports=self.allowed_target_ports)
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
        keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kid")]
        if len(keys) > _MAX_JWKS_KEYS:
            # Refuse an oversized key set rather than installing it (TM-I-09/H-2). On the
            # refresh path this is caught and the previous cache is served; at seed time it
            # fails fast. The signature allow-list still gates forgery, but a key-count cap
            # closes the unbounded-install vector if the IdP channel is ever compromised.
            raise OIDCError(f"JWKS has {len(keys)} keys, exceeds cap {_MAX_JWKS_KEYS}")
        self._keys = {k["kid"]: k for k in keys}
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
                # The exception TYPE carries the diagnosis here: several httpx timeout
                # errors stringify to "", so `{exc}` alone logs a blank reason for the
                # most common IdP misconfiguration there is — an unreachable JWKS host
                # (blocked egress port, NetworkPolicy, firewall). Naming the issuer
                # matters too: with several issuers configured, "refresh failed" is
                # otherwise unattributable.
                detail = str(exc) or "(no detail)"
                logger.warning(
                    f"OIDC JWKS refresh failed for issuer {self._cfg.issuer!r} "
                    f"(serving from cache if present): {type(exc).__name__}: {detail}"
                )
        if kid in self._keys:
            return self._keys[kid]
        raise OIDCError(f"no JWKS key for kid={kid!r} (unknown key or IdP unreachable)")

    async def _refresh(self) -> None:
        uri = await self._resolve_jwks_uri()
        # Fetch through the shared egress guard so the JWKS path uses the same SSRF policy
        # as every other server-side fetch (H-1). follow_redirects=False keeps the prior
        # behaviour (an IdP redirect is not chased to another origin), and the guard
        # re-validates the host on the request hop. validate_target_url stays as the
        # explicit pre-flight check on the resolved/discovered URI.
        validate_target_url(
            uri, allow_private=self._cfg.allow_private_targets, allowed_ports=self._cfg.allowed_target_ports
        )
        async with build_guarded_client(
            allow_private=self._cfg.allow_private_targets,
            allowed_ports=self._cfg.allowed_target_ports,
            follow_redirects=False,
            timeout=self._cfg.http_timeout,
        ) as client:
            resp = await client.get(uri)
            resp.raise_for_status()
            self._install(resp.json())
        logger.info(f"OIDC JWKS refreshed from {uri} ({len(self._keys)} key(s))")

    async def _resolve_jwks_uri(self) -> str:
        if self._discovered_jwks_uri:
            return self._discovered_jwks_uri
        # OIDC discovery: <issuer>/.well-known/openid-configuration → jwks_uri.
        disco = self._cfg.issuer.rstrip("/") + "/.well-known/openid-configuration"
        validate_target_url(
            disco, allow_private=self._cfg.allow_private_targets, allowed_ports=self._cfg.allowed_target_ports
        )
        async with build_guarded_client(
            allow_private=self._cfg.allow_private_targets,
            allowed_ports=self._cfg.allowed_target_ports,
            follow_redirects=False,
            timeout=self._cfg.http_timeout,
        ) as client:
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
        # Attached after startup, once Redis exists (the validator is built before it).
        # Until then it is None, and every elevated grant is refused — which is also the
        # permanent state in embedded mode, where there is no shared store at all.
        self._grant_store: Optional[GrantConsumptionStore] = None

    @property
    def jwks(self) -> JWKSCache:
        return self._jwks

    @property
    def config(self) -> OIDCConfig:
        return self._cfg

    def attach_grant_store(self, store: Optional[GrantConsumptionStore]) -> None:
        self._grant_store = store

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

        principal = self._principal_from_claims(claims)
        return await self._apply_grant(claims, principal)

    async def _apply_grant(self, claims: dict[str, Any], principal: Principal) -> Principal:
        """Raise this principal's ceiling if the token carries a valid grant (ADR-0013 §11).

        Two orderings here are load-bearing and both are easy to get backwards.

        **The plane is consulted before the union.** A grant lifts a *ceiling*, so on an
        issuer that has none there is nothing to lift and the claim is ignored outright. Do
        the union first and a tenant `viewer` whose own IdP can be made to emit the claim
        gains `tools:call` on their own stack — §6a's escalation one layer up, sourced from
        the tenant's own IdP.

        **The union happens after the ceiling has been applied**, not instead of it. The
        grant adds exactly what it names on top of the capped base; it is not an alternative
        route to authority, so a subject whose groups map to nothing still ends up with
        nothing.
        """
        raw = claims.get(self._cfg.grant_claim)
        if raw is None:
            return principal

        ceiling = PLANE_SCOPE_CEILING[self._cfg.plane]
        if ceiling is None:
            # Anomalous rather than dangerous — but worth a line, because a tenant IdP
            # emitting this claim means either a misconfigured hook or someone probing.
            logger.warning(
                f"token from {self._cfg.issuer!r} carries a {self._cfg.grant_claim!r} claim, but that "
                f"issuer is on the {self._cfg.plane!r} plane and has no scope ceiling to raise. "
                f"Ignoring the claim; it grants nothing (ADR-0013 §11)."
            )
            return principal

        if not principal.scopes:
            # An authenticated subject whose groups map to no role. The grant lifts a
            # ceiling; it does not replace the group mapping, which stays load-bearing for
            # exactly the population §6a exists to constrain.
            logger.warning(
                f"subject {principal.subject!r} presented an elevated grant but no group maps to a "
                f"role; the grant raises a ceiling and is not an alternative route to authority."
            )
            return principal

        try:
            grant: ElevatedGrant = await verify_grant(
                raw,
                tenant_id=self._cfg.tenant_id,
                step_up_acr=self._cfg.step_up_acr,
                acr=claims.get("acr"),
                auth_time=claims.get("auth_time"),
                store=self._grant_store,
                leeway=self._cfg.leeway,
            )
        except GrantError as exc:
            metrics.elevated_grants_total.labels(outcome="refused").inc()
            logger.warning(f"elevated grant refused for subject from {self._cfg.issuer!r}: {exc}")
            # Refuse the whole token rather than serving the unelevated principal — see
            # GrantError's docstring for why the quiet fall-back is the worse failure.
            raise OIDCError(f"elevated grant refused: {exc}")

        metrics.elevated_grants_total.labels(outcome="accepted").inc()
        logger.info(
            f"elevated grant {grant.id!r} accepted for {principal.subject!r} on tenant {grant.tenant!r}: "
            f"+{sorted(grant.scopes)} until {grant.expires_at:.0f} (single_use={grant.single_use})"
        )
        return Principal(
            subject=principal.subject,
            scopes=principal.scopes | grant.scopes,
            auth_method=principal.auth_method,
            grant_id=grant.id,
        )

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

        # Apply the plane ceiling again at validation time (§6a). Not redundant with the
        # startup check: config can be reloaded and ROLE_SCOPES can gain a scope, and a
        # startup-only check is a claim about one moment rather than about every request.
        ceiling = PLANE_SCOPE_CEILING[self._cfg.plane]
        if ceiling is not None:
            dropped = scopes - ceiling
            if dropped:
                logger.warning(
                    f"OIDC issuer {self._cfg.issuer!r} ({self._cfg.plane} plane) yielded scopes outside its "
                    f"ceiling and they were dropped: {sorted(dropped)}. This should have been refused at "
                    f"startup — treat it as a configuration or role-table drift."
                )
            scopes &= ceiling

        # The subject is qualified by its issuer. `sub` is unique *within* an issuer, not
        # globally: `admin` at the tenant IdP and `admin` at the provider IdP are two
        # different humans, and collapsing them puts both on one line of the tenant's
        # hash-chained audit — a failure with no symptom, because both requests succeed.
        return Principal(
            subject=f"oidc:{self._cfg.issuer}#{subject}",
            scopes=frozenset(scopes),
            auth_method=AUTH_METHOD_OIDC,
        )


class MultiIssuerValidator:
    """Routes a token to **one** issuer's validator, then verifies against only that one.

    This class exists because of a single trap. The obvious way to accept two issuers is
    to pass a list to ``jwt.decode(issuer=[...])`` over a merged key set — and that accepts
    a token signed by issuer A's key while claiming ``iss: B``. PyJWT is behaving correctly:
    it checks that ``iss`` is in the accepted list, and the key it was handed verified the
    signature. The composition is what is wrong, and the result is a complete impersonation
    primitive: a tenant IdP operator mints themselves provider identity on their own gateway.

    So the issuer is resolved **first**, from the unverified claims, and used only to pick a
    validator. Every subsequent check — signature key, audience, ``issuer=`` pin, group
    mapping, scope ceiling — comes from that one issuer's config. Reading ``iss`` before
    verification is safe precisely because it is used to *select* a verifier and never to
    grant anything; an attacker choosing their own issuer only chooses whose keys must
    validate their signature.

    ``tests/test_multi_issuer_isolation.py`` pins all of this, including the converse
    direction, because an implementation can easily get one direction right.
    """

    def __init__(self, configs: list[OIDCConfig]) -> None:
        if not configs:
            raise ValueError("MultiIssuerValidator needs at least one issuer")
        self._validators: dict[str, OIDCValidator] = {}
        for cfg in configs:
            if cfg.issuer in self._validators:
                # One of the two entries would silently never apply, and which one wins
                # would be an ordering accident.
                raise ValueError(f"duplicate gateway.oidc issuer {cfg.issuer!r}")
            self._validators[cfg.issuer] = OIDCValidator(cfg)

    @property
    def issuers(self) -> list[str]:
        return list(self._validators)

    def for_issuer(self, issuer: str) -> OIDCValidator:
        return self._validators[issuer]

    def seed(self, issuer: str, jwks: dict[str, Any]) -> None:
        """Install a key set for one issuer (startup warm-up / tests)."""
        self._validators[issuer].jwks.seed(jwks)

    def attach_grant_store(self, store: Optional[GrantConsumptionStore]) -> None:
        """Give every issuer the elevated-grant consumption store (ADR-0013 §11a).

        Called from the lifespan once Redis exists, because the authenticator is built at
        import time and Redis is not up then. Before this runs — and forever in embedded
        mode, which never calls it — elevated grants are refused.
        """
        for validator in self._validators.values():
            validator.attach_grant_store(store)

    async def validate(self, token: str) -> Principal:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise OIDCError(f"malformed JWT: {exc}")
        issuer = unverified.get("iss")
        if not issuer or not isinstance(issuer, str):
            # Nothing to route on, and there is no safe default — falling back to "the
            # first configured issuer" would be the same bug as a shared key set.
            raise OIDCError("JWT has no usable iss claim; cannot select an issuer")
        validator = self._validators.get(issuer)
        if validator is None:
            raise OIDCError(f"issuer {issuer!r} is not configured")
        return await validator.validate(token)


def _issuer_config(entry: dict, cfg: dict, *, default_plane: str = PLANE_TENANT) -> OIDCConfig:
    from device_mcp_gateway.security.url_policy import resolve_allow_private, resolve_allowed_ports

    # The gateway's own tenant identity is a property of the deployment, not of an issuer —
    # one gateway serves one tenant (ADR-0004) — so it is read from `gateway.tenant_id` and
    # handed to every issuer entry rather than repeated per entry.
    tenant_id = (cfg.get("gateway", {}) or {}).get("tenant_id") or None

    return OIDCConfig(
        issuer=entry.get("issuer", ""),
        audience=entry.get("audience", ""),
        group_roles=dict(entry.get("group_roles", {}) or {}),
        plane=entry.get("plane", default_plane),
        tenant_id=tenant_id,
        step_up_acr=tuple(entry.get("step_up_acr") or ()),
        grant_claim=entry.get("grant_claim", GRANT_CLAIM_DEFAULT),
        jwks_uri=entry.get("jwks_uri"),
        groups_claim=entry.get("groups_claim", "groups"),
        subject_claim=entry.get("subject_claim", "sub"),
        algorithms=tuple(entry.get("algorithms") or ("RS256",)),
        leeway=int(entry.get("leeway", 60)),
        jwks_cache_ttl=int(entry.get("jwks_cache_ttl", 600)),
        jwks_min_refresh_interval=int(entry.get("jwks_min_refresh_interval", 30)),
        http_timeout=float(entry.get("http_timeout", 5.0)),
        allow_private_targets=resolve_allow_private(cfg),
        allowed_target_ports=resolve_allowed_ports(cfg),
    )


def build_oidc_validator(cfg: dict) -> Optional[MultiIssuerValidator]:
    """Construct the inbound OIDC validator, or ``None`` if OIDC is not enabled.

    Reads ``gateway.oidc`` (inbound auth lives under ``gateway.*``, alongside
    ``api_key`` / ``rbac``). Resolution failures raise ``ValueError`` so a misconfigured
    IdP fails fast at startup rather than on the first login.

    Two accepted shapes. The **legacy single-issuer** form (``issuer``/``audience``/
    ``group_roles`` at the top level) keeps working untouched and lands on the tenant
    plane — a security change that forced every existing operator through a config
    migration would get deferred, and then nobody would get the isolation. The
    **multi-issuer** form takes a list under ``issuers``, each entry declaring its own
    ``plane`` and its own ``group_roles`` (ADR-0013 §6a: no shared or fallback mapping).
    """
    oidc_cfg = (cfg.get("gateway", {}) or {}).get("oidc", {}) or {}
    if not oidc_cfg.get("enabled", False):
        return None

    entries = oidc_cfg.get("issuers")
    if entries:
        if oidc_cfg.get("issuer"):
            raise ValueError(
                "gateway.oidc sets both 'issuer' and 'issuers'; use one form or the other so "
                "there is no question which mapping applies"
            )
        configs = [_issuer_config(e, cfg) for e in entries]
    else:
        configs = [_issuer_config(oidc_cfg, cfg)]

    validator = MultiIssuerValidator(configs)
    for c in configs:
        logger.info(
            f"OIDC inbound auth enabled: issuer={c.issuer} plane={c.plane} audience={c.audience} "
            f"algs={list(c.algorithms)} groups_claim={c.groups_claim} "
            f"roles={sorted(set(c.group_roles.values()))}"
        )
    return validator
