# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Inbound RBAC for the gateway API (F15).

The seam is deliberately shaped for the long term: a request authenticates to a
``Principal`` (subject + scopes + auth method), and routes authorize on individual
**scopes** — not a coarse role string. Static API keys are the current
implementation (key → role → scopes); swapping to JWT/OIDC later changes only
``Authenticator``/``authenticate_request`` — every route's ``require_scope(...)`` and
the audit-log ``subject`` stay put.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Union

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, audit_event

if TYPE_CHECKING:
    from device_mcp_gateway.oidc import OIDCValidator

# --- Scopes ------------------------------------------------------------------

SCOPE_DEVICES_READ = "devices:read"
SCOPE_DEVICES_WRITE = "devices:write"
SCOPE_TOOLS_CALL = "tools:call"
SCOPE_METRICS_READ = "metrics:read"

ALL_SCOPES: frozenset[str] = frozenset({SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_TOOLS_CALL, SCOPE_METRICS_READ})

# Roles are just named bundles of scopes. New roles = new entries here; routes never
# reference roles, only scopes, so adding one never touches a call site. The full matrix
# (and the IdP group → role mapping) lives in docs/rbac-roles.md; ADR-0007 is the why.
ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": ALL_SCOPES,
    # Manage the fleet (onboard/edit/remove devices, DLQ recovery) but not invoke tools.
    "operator": frozenset({SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_METRICS_READ}),
    "viewer": frozenset({SCOPE_DEVICES_READ, SCOPE_METRICS_READ}),
    # Observability / compliance only — no device access.
    "auditor": frozenset({SCOPE_METRICS_READ}),
    # Machine identity: an MCP client/agent that discovers and invokes tools.
    "caller": frozenset({SCOPE_DEVICES_READ, SCOPE_TOOLS_CALL}),
}


@dataclass(frozen=True)
class Principal:
    """The authenticated caller: who they are, what they may do, how they proved it."""

    subject: str
    scopes: frozenset[str]
    auth_method: str

    def has(self, scope: str) -> bool:
        return scope in self.scopes


# Auth-disabled principal: full access, used when no keys are configured at all
# (preserves the single-operator / local-dev behaviour of "no key → no auth").
ANONYMOUS = Principal(subject="anonymous", scopes=ALL_SCOPES, auth_method="none")


def scopes_for_role(role: str) -> frozenset[str]:
    try:
        return ROLE_SCOPES[role]
    except KeyError:
        raise ValueError(f"Unknown RBAC role '{role}' (known roles: {', '.join(sorted(ROLE_SCOPES))})")


class Authenticator:
    """Resolves bearer credentials to a Principal via static API keys."""

    def __init__(self, keys: dict[str, Principal], enabled: bool) -> None:
        self._keys = keys
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def authenticate(self, credentials: Optional[HTTPAuthorizationCredentials]) -> Principal:
        if not self._enabled:
            return ANONYMOUS
        token = credentials.credentials if credentials else None
        principal = self._match(token) if token else None
        if principal is None:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return principal

    async def authenticate_async(self, credentials: Optional[HTTPAuthorizationCredentials]) -> Principal:
        """Async entry point (uniform with CompositeAuthenticator). No I/O here —
        static-key matching is in-memory — so this just wraps the sync path."""
        return self.authenticate(credentials)

    def match(self, token: str) -> Optional[Principal]:
        """Public, timing-safe lookup of a static key → Principal (or None). The
        composite authenticator uses this for opaque (non-JWT) tokens."""
        return self._match(token)

    def _match(self, token: str) -> Optional[Principal]:
        # Constant-time compare against every configured key; never early-exit on
        # the token contents (timing-safe), even though the key set is small.
        matched: Optional[Principal] = None
        for known, principal in self._keys.items():
            if hmac.compare_digest(token, known):
                matched = principal
        return matched


_UNAUTHORIZED = HTTPException(
    status_code=401,
    detail="Unauthorized",
    headers={"WWW-Authenticate": "Bearer"},
)


def _looks_like_jwt(token: str) -> bool:
    """A compact JWS has exactly three non-empty dot-separated segments. Cheap shape
    check so we only run JWT crypto on JWT-shaped tokens; opaque keys skip it."""
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


class CompositeAuthenticator:
    """Federated OIDC first, static break-glass keys second, else 401 (ADR-0007).

    Order matches the ADR: a valid OIDC JWT → its mapped scopes; **else** a configured
    static key; **else** 401. Static keys keep working when the IdP/JWKS is unreachable,
    because an opaque key never enters the OIDC path and an OIDC failure falls through to
    the key match (TM-I-12 — fail closed for OIDC, open to break-glass keys).
    """

    def __init__(self, *, static: Authenticator, oidc: "OIDCValidator") -> None:
        self._static = static
        self._oidc = oidc

    @property
    def enabled(self) -> bool:
        # OIDC being configured is itself auth — true even with zero static keys.
        return True

    @property
    def static(self) -> Authenticator:
        return self._static

    async def authenticate_async(self, credentials: Optional[HTTPAuthorizationCredentials]) -> Principal:
        token = credentials.credentials if credentials else None
        if not token:
            raise _UNAUTHORIZED

        principal: Optional[Principal] = None
        if _looks_like_jwt(token):
            from device_mcp_gateway.oidc import OIDCError

            try:
                principal = await self._oidc.validate(token)
            except OIDCError as exc:
                # Not a valid JWT for us — fall through to static keys (it may be a
                # break-glass key that happens to be JWT-shaped, or the IdP is down).
                logger.debug(f"OIDC validation fell through to static keys: {exc}")
                principal = None

        if principal is None:
            principal = self._static.match(token)

        if principal is None:
            raise _UNAUTHORIZED
        return principal


def build_static_authenticator(cfg: dict) -> Authenticator:
    """Build the static-API-key Authenticator from config + env.

    Precedence/back-compat:
      - ``MCP_GATEWAY_API_KEY`` / ``gateway.api_key`` → an **admin** key (today's
        single-key behaviour, unchanged).
      - ``MCP_ADMIN_KEY`` / ``MCP_VIEWER_KEY`` → convenience role keys.
      - ``gateway.rbac`` → explicit ``[{name, key, role}]`` scoped keys.
      - No keys anywhere → auth **disabled** (all requests permitted).
    """
    gateway = cfg.get("gateway", {})
    keys: dict[str, Principal] = {}

    def _add(token: Optional[str], role: str, name: str) -> None:
        if not token:
            return
        keys[token] = Principal(subject=f"key:{name}", scopes=scopes_for_role(role), auth_method="api_key")

    _add(os.getenv("MCP_GATEWAY_API_KEY") or gateway.get("api_key"), "admin", "legacy")
    _add(os.getenv("MCP_ADMIN_KEY"), "admin", "admin")
    _add(os.getenv("MCP_VIEWER_KEY"), "viewer", "viewer")
    for entry in gateway.get("rbac", []) or []:
        _add(entry.get("key"), entry.get("role", "viewer"), entry.get("name") or entry.get("role", "viewer"))

    enabled = len(keys) > 0
    if enabled:
        logger.info(f"Gateway static-key auth: {len(keys)} API key(s) configured")
    return Authenticator(keys, enabled)


def build_authenticator(cfg: dict) -> Union[Authenticator, CompositeAuthenticator]:
    """Build the gateway authenticator (ADR-0007 composite, or static-only).

    Static API keys are always built (break-glass / bootstrap). If ``gateway.oidc`` is
    enabled, the result is a :class:`CompositeAuthenticator` (OIDC JWT → else static key
    → else 401); otherwise the plain :class:`Authenticator` is returned unchanged so
    existing single-key / no-key deployments behave exactly as before.
    """
    static = build_static_authenticator(cfg)

    from device_mcp_gateway.oidc import build_oidc_validator

    oidc = build_oidc_validator(cfg)
    if oidc is None:
        if not static.enabled:
            logger.warning("Gateway RBAC disabled: no API keys configured — all requests permitted")
        return static

    if not static.enabled:
        # OIDC alone authenticates, but with no static key there is no way in when the
        # IdP/JWKS is unreachable. ADR-0007 keeps at least one admin key as documented
        # break-glass — warn loudly so an operator does not lock themselves out.
        logger.warning(
            "OIDC is enabled but no static break-glass key is configured (MCP_ADMIN_KEY / "
            "gateway.rbac). If the IdP or its JWKS endpoint is unreachable, no one can "
            "authenticate. Configure at least one admin key as break-glass (ADR-0007)."
        )
    return CompositeAuthenticator(static=static, oidc=oidc)


# --- FastAPI dependencies ----------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


def _audit_target(request: Request) -> str:
    """`METHOD /path` for the audit target, resolved defensively (works on fakes too)."""
    method = getattr(request, "method", "?")
    path = getattr(getattr(request, "url", None), "path", "?")
    return f"{method} {path}"


def _audit_rid(request: Request) -> str:
    return getattr(getattr(request, "state", None), "request_id", "-")


async def authenticate_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer),
) -> None:
    """Router-level dependency: resolve the caller and stash the Principal.

    A failed authentication (401) is audited with the request target (F-55) so
    access-denied events are answerable from the log, not just successful access.
    """
    authenticator = request.app.state.authenticator
    try:
        request.state.principal = await authenticator.authenticate_async(credentials)
    except HTTPException as exc:
        if exc.status_code == 401:
            audit_event(
                "auth.authenticate",
                subject="unauthenticated",
                outcome=AUDIT_OUTCOME_DENIED,
                rid=_audit_rid(request),
                target=_audit_target(request),
                reason="invalid_or_missing_token",
            )
        raise


def require_scope(scope: str):
    """Route-level dependency factory: 403 unless the Principal holds ``scope``."""

    async def _dep(request: Request) -> None:
        principal: Optional[Principal] = getattr(request.state, "principal", None)
        if principal is None or not principal.has(scope):
            # Audit the authorization denial with the actor + the scope they lacked (F-55).
            audit_event(
                "authz.check",
                subject=principal.subject if principal is not None else "unauthenticated",
                outcome=AUDIT_OUTCOME_DENIED,
                rid=_audit_rid(request),
                target=_audit_target(request),
                reason=f"missing_scope:{scope}",
            )
            raise HTTPException(status_code=403, detail=f"Missing required scope: {scope}")

    return _dep
