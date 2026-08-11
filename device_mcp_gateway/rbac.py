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
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Union

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, audit_event

if TYPE_CHECKING:
    from device_mcp_gateway.oidc import OIDCValidator

# --- Scopes ------------------------------------------------------------------

SCOPE_DEVICES_READ = "devices:read"
SCOPE_DEVICES_WRITE = "devices:write"
SCOPE_TOOLS_CALL = "tools:call"
SCOPE_METRICS_READ = "metrics:read"
# Backup/restore (ADR-0011). Three scopes rather than one because the three grants are
# genuinely different: reading an archive exfiltrates every device's URL and configuration
# even without the key; writing one can reinstate devices; and a *portable* export is a
# complete set of live credentials under a single passphrase. The last is never implied by
# the other two — it has to be asked for by name.
SCOPE_BACKUP_READ = "backup:read"
SCOPE_BACKUP_WRITE = "backup:write"
SCOPE_BACKUP_EXPORT_PORTABLE = "backup:export-portable"

ALL_SCOPES: frozenset[str] = frozenset(
    {
        SCOPE_DEVICES_READ,
        SCOPE_DEVICES_WRITE,
        SCOPE_TOOLS_CALL,
        SCOPE_METRICS_READ,
        SCOPE_BACKUP_READ,
        SCOPE_BACKUP_WRITE,
        SCOPE_BACKUP_EXPORT_PORTABLE,
    }
)

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
    # Machine identity: a scheduled backup job. Deliberately NOT admin — a cron entry
    # that runs nightly should not carry the ability to invoke tools or edit the fleet.
    # Equally deliberately without `backup:export-portable`: routine backups are the
    # ciphertext kind, and the key-independent archive is an operator decision, not a
    # thing a scheduler holds standing permission to produce.
    "backup": frozenset({SCOPE_BACKUP_READ, SCOPE_BACKUP_WRITE}),
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


# Fixed, small set of failure labels. The raw OIDCError text must NEVER become a metric
# label: it embeds attacker-controlled JWT contents (kid, alg), which would let a caller
# mint unbounded Prometheus time series just by varying a header (review item 10).
_OIDC_FAILURE_REASONS = ("jwks_unavailable", "expired", "invalid_token", "bad_algorithm", "malformed", "other")

# Seconds between OIDC-failure warnings. A forged-JWT flood or an IdP outage would
# otherwise emit one line per request; one warning per minute carrying the suppressed
# count keeps the signal without the flood.
_OIDC_WARN_INTERVAL = 60.0


def _classify_oidc_failure(message: str) -> str:
    """Map an OIDCError message onto :data:`_OIDC_FAILURE_REASONS`.

    Substring matching against our own raised messages (``oidc.py``) — deliberately
    coarse, because the value is telling an operator "the IdP is down" apart from
    "someone is forging tokens", not reproducing the exception.
    """
    text = (message or "").lower()
    if "jwks" in text or "unreachable" in text or "discovery" in text:
        return "jwks_unavailable"
    if "expired" in text:
        return "expired"
    if "alg " in text or "allow-list" in text:
        return "bad_algorithm"
    if "malformed" in text or "no kid" in text or "missing subject" in text:
        return "malformed"
    if "validation failed" in text or "signature" in text:
        return "invalid_token"
    return "other"


class CompositeAuthenticator:
    """Federated OIDC first, static break-glass keys second, else 401 (ADR-0007).

    Order matches the ADR: a valid OIDC JWT → its mapped scopes; **else** a configured
    static key; **else** 401. Static keys keep working when the IdP/JWKS is unreachable,
    because an opaque key never enters the OIDC path and an OIDC failure falls through to
    the key match (TM-I-12 — fail closed for OIDC, open to break-glass keys).

    That fall-through used to be logged at ``debug``, which made the *degraded* state
    invisible: an IdP or JWKS outage silently reduced the whole deployment to
    break-glass-keys-only, and forged-JWT probing produced no signal at all (review item
    10). It now increments ``mcp_oidc_validation_failures_total`` and emits a rate-limited
    WARNING. Falling through is still the correct behaviour — it is what keeps break-glass
    working — it just is not silent any more.
    """

    def __init__(self, *, static: Authenticator, oidc: "OIDCValidator") -> None:
        self._static = static
        self._oidc = oidc
        self._oidc_warn_last = 0.0
        self._oidc_warn_suppressed = 0

    def _note_oidc_failure(self, exc: Exception) -> None:
        """Count every failure; warn at most once per :data:`_OIDC_WARN_INTERVAL`."""
        message = str(exc)
        reason = _classify_oidc_failure(message)
        metrics.oidc_validation_failures_total.labels(reason=reason).inc()

        now = time.monotonic()
        if now - self._oidc_warn_last < _OIDC_WARN_INTERVAL:
            self._oidc_warn_suppressed += 1
            return
        suppressed = self._oidc_warn_suppressed
        self._oidc_warn_last = now
        self._oidc_warn_suppressed = 0
        extra = f" ({suppressed} similar suppressed in the last {int(_OIDC_WARN_INTERVAL)}s)" if suppressed else ""
        logger.warning(
            f"OIDC validation failed (reason={reason}), falling through to static break-glass "
            f"keys{extra}: {message}. If this persists, the IdP or its JWKS endpoint is "
            "unreachable and only break-glass keys can authenticate — see "
            "mcp_oidc_validation_failures_total."
        )

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
                # Counted + rate-limit-warned so the degraded state is not silent.
                self._note_oidc_failure(exc)
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
        for name, why in weak_static_keys(cfg):
            logger.warning(
                f"Gateway API key '{name}' is weak ({why}). It is a full bearer credential — "
                "with OIDC enabled it is also the break-glass key that still works when the "
                "IdP is down. Generate a real one: openssl rand -hex 32. "
                "(Distributed mode refuses to start on this; override with "
                "gateway.allow_weak_keys: true.)"
            )
    return Authenticator(keys, enabled)


# Guessable regardless of length — the review's example was literally MCP_ADMIN_KEY=admin.
_WEAK_KEY_VALUES = frozenset(
    {
        "admin",
        "administrator",
        "password",
        "passwd",
        "changeme",
        "change-me",
        "secret",
        "test",
        "testing",
        "dev",
        "development",
        "default",
        "mcp",
        "gateway",
        "key",
        "apikey",
        "api-key",
        "token",
        "letmein",
        "hunter2",
        "12345678",
        "please-change-me",
    }
)

# Comfortably below everything this project generates or documents: the LITE bootstrap
# uses secrets.token_urlsafe(24) (32 chars) and the docs use `openssl rand -hex 24/32`
# (48/64 chars). So this flags hand-typed keys without breaking a real deployment.
_MIN_KEY_LENGTH = 16


def weak_static_keys(cfg: dict) -> list[tuple[str, str]]:
    """Static API keys that are too guessable to be a bearer credential (review item 11).

    Returns ``[(source_name, reason)]`` — empty when every configured key is acceptable,
    and empty when no keys are configured at all (auth-disabled is the separate F-23
    finding, with its own gate; reporting it here too would just be noise).

    Deliberately a *shape* check — length plus a small guessable-value list — not an
    entropy estimate. Shannon entropy over a short string is nearly meaningless and would
    reject legitimate high-entropy keys that happen to look repetitive, while a length
    floor catches the actual failure mode: someone typing a memorable key by hand.
    """
    gateway = cfg.get("gateway", {})
    found: list[tuple[str, str]] = []

    def _check(token: Optional[str], name: str) -> None:
        if not token:
            return
        if token.strip().lower() in _WEAK_KEY_VALUES:
            found.append((name, "a common, guessable value"))
        elif len(token) < _MIN_KEY_LENGTH:
            found.append((name, f"only {len(token)} characters; use at least {_MIN_KEY_LENGTH}"))

    _check(os.getenv("MCP_GATEWAY_API_KEY") or gateway.get("api_key"), "MCP_GATEWAY_API_KEY/gateway.api_key")
    _check(os.getenv("MCP_ADMIN_KEY"), "MCP_ADMIN_KEY")
    _check(os.getenv("MCP_VIEWER_KEY"), "MCP_VIEWER_KEY")
    for entry in gateway.get("rbac", []) or []:
        _check(entry.get("key"), f"gateway.rbac[{entry.get('name') or entry.get('role', '?')}]")
    return found


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
