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
from typing import Optional

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, audit_event

# --- Scopes ------------------------------------------------------------------

SCOPE_DEVICES_READ = "devices:read"
SCOPE_DEVICES_WRITE = "devices:write"
SCOPE_TOOLS_CALL = "tools:call"
SCOPE_METRICS_READ = "metrics:read"

ALL_SCOPES: frozenset[str] = frozenset({SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_TOOLS_CALL, SCOPE_METRICS_READ})

# Roles are just named bundles of scopes. New roles = new entries here; routes never
# reference roles, only scopes, so adding one never touches a call site.
ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": ALL_SCOPES,
    "viewer": frozenset({SCOPE_DEVICES_READ, SCOPE_METRICS_READ}),
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

    def _match(self, token: str) -> Optional[Principal]:
        # Constant-time compare against every configured key; never early-exit on
        # the token contents (timing-safe), even though the key set is small.
        matched: Optional[Principal] = None
        for known, principal in self._keys.items():
            if hmac.compare_digest(token, known):
                matched = principal
        return matched


def build_authenticator(cfg: dict) -> Authenticator:
    """Build the gateway Authenticator from config + env.

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
        logger.info(f"Gateway RBAC enabled: {len(keys)} API key(s) configured")
    else:
        logger.warning("Gateway RBAC disabled: no API keys configured — all requests permitted")
    return Authenticator(keys, enabled)


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
    authenticator: Authenticator = request.app.state.authenticator
    try:
        request.state.principal = authenticator.authenticate(credentials)
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
