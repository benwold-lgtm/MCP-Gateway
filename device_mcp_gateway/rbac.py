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
import asyncio
import concurrent.futures
import os
import time
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Optional, Union

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, audit_event

if TYPE_CHECKING:
    from device_mcp_gateway.oidc import MultiIssuerValidator

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
    #: True when this principal authenticated with a ``break_glass: true`` credential
    #: (ADR-0023). Carried on the Principal rather than recomputed at each call site so the
    #: audit event, the metrics and the reactivation-frequency signal all read one fact.
    break_glass: bool = False

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

    def __init__(self, *, static: Authenticator, oidc: "MultiIssuerValidator") -> None:
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
        # The "check whether your IdP is reachable" advice is only true for the reachability
        # class. Appended unconditionally it actively misdirects: a forged or expired token is
        # the gateway working as designed, and sending the operator to look at IdP
        # connectivity buries the real reason under a wrong one.
        advice = (
            " If this persists, the IdP or its JWKS endpoint is unreachable and only "
            "break-glass keys can authenticate — see mcp_oidc_validation_failures_total."
            if reason == "jwks_unavailable"
            else " This token was refused on its own merits, not for IdP reachability — see "
            "mcp_oidc_validation_failures_total."
        )
        logger.warning(
            f"OIDC validation failed (reason={reason}), falling through to static break-glass "
            f"keys{extra}: {message}.{advice}"
        )

    @property
    def enabled(self) -> bool:
        # OIDC being configured is itself auth — true even with zero static keys.
        return True

    @property
    def static(self) -> Authenticator:
        return self._static

    @property
    def oidc(self) -> "MultiIssuerValidator":
        """The federated (OIDC) half of the composite authenticator."""
        return self._oidc

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


class BreakGlassConfigError(ValueError):
    """A ``break_glass: true`` entry is malformed. Always fatal, in every mode.

    Unlike the weak-key gate, this has no ``allow_...`` override. A misconfigured break-glass
    entry is not a weaker version of a working one — it is an entry that would authenticate
    somebody the audit cannot name, which is the whole problem ADR-0023 exists to close.
    """


def _resolve_break_glass_key(ref_raw: str, resolver: Optional[object], name: str) -> str:
    """Read a flagged entry's key through the ADR-0018 resolver.

    Startup is synchronous and ``CredentialResolver.resolve`` is not, so the coroutine is run
    here. Reusing the resolver rather than reading the file directly is deliberate: it carries
    the ownership checks that decide whether a credential file is actually private to this
    workload, and a second reader would be a second place for that policy to drift.
    """
    from device_mcp_gateway.credentials import CredentialRef, ResolverError

    if resolver is None:
        raise BreakGlassConfigError(
            f"gateway.rbac[{name!r}] is break_glass but no credential resolver is configured. "
            "A flagged entry takes a secret:// reference (ADR-0023), which needs "
            "gateway.credentials.root (or MCP_CREDENTIAL_ROOT) set."
        )
    try:
        ref = CredentialRef.parse(ref_raw)
    except ResolverError as exc:
        raise BreakGlassConfigError(f"gateway.rbac[{name!r}] has an unusable secret reference: {exc}") from exc

    async def _go() -> str:
        return await resolver.resolve(ref)  # type: ignore[attr-defined]

    try:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(_go())
        # Already inside a loop (a test, or an embedded host). Run it on its own.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, _go()).result()
    except ResolverError as exc:
        raise BreakGlassConfigError(
            f"gateway.rbac[{name!r}] is break_glass and its key could not be resolved: {exc}. "
            "Refusing to start — a break-glass path that is broken is discovered during the "
            "incident it exists for."
        ) from exc


#: Starting default from ADR-0023 §3 — a widely-used compliance rotation cadence, instrumented
#: and tuned from operating history rather than fixed here.
DEFAULT_BREAK_GLASS_EXPIRY_DAYS = 90

#: §3's escalating notice: two weeks out, then three days out. Not a silent cutoff — a
#: break-glass credential that expires quietly is discovered dead at the worst possible moment.
_BREAK_GLASS_WARN_DAYS = (14, 3)


def _break_glass_days_remaining(entry: dict, name: str, expiry_days: int, *, today: date) -> int:
    """Days left on a flagged entry. Raises :class:`BreakGlassConfigError` if undatable.

    ``issued`` is mandatory on a flagged entry for the same reason ``name`` is: an omitted
    field must not silently produce the behaviour the ADR forbids. Without an issue date the
    credential has indefinite validity, which is exactly what §3 says it must not have.
    """
    raw = entry.get("issued")
    if not raw:
        raise BreakGlassConfigError(
            f"gateway.rbac[{name!r}] is break_glass and has no 'issued' date. Refusing to start — "
            "a flagged credential carries a real lifetime (ADR-0023 §3), and an entry with no "
            "issue date has indefinite validity, which is the thing that rule exists to prevent."
        )
    try:
        issued = date.fromisoformat(str(raw))
    except ValueError as exc:
        raise BreakGlassConfigError(
            f"gateway.rbac[{name!r}] has an unparseable 'issued' date {raw!r}; expected YYYY-MM-DD."
        ) from exc
    if issued > today:
        # A future date extends validity, and the likeliest cause is a typo in the year. Left
        # unchecked it is a silent grant of extra lifetime, which is the same class of error as
        # an absent date.
        raise BreakGlassConfigError(
            f"gateway.rbac[{name!r}] has an 'issued' date in the future ({issued}). Refusing to "
            "start — a future issue date silently extends the credential's lifetime."
        )
    return expiry_days - (today - issued).days


def _break_glass_entries(cfg: dict) -> list[str]:
    """Names of the configured break-glass entries, for logging. Validates nothing."""
    out = []
    for entry in (cfg.get("gateway", {}) or {}).get("rbac", []) or []:
        if isinstance(entry, dict) and entry.get("break_glass"):
            out.append(str(entry.get("name") or "<unnamed>"))
    return out


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

    def _add(token: Optional[str], role: str, name: str, *, break_glass: bool = False) -> None:
        if not token:
            return
        keys[token] = Principal(
            subject=f"key:{name}",
            scopes=scopes_for_role(role),
            auth_method="break_glass" if break_glass else "api_key",
            break_glass=break_glass,
        )

    _add(os.getenv("MCP_GATEWAY_API_KEY") or gateway.get("api_key"), "admin", "legacy")
    _add(os.getenv("MCP_ADMIN_KEY"), "admin", "admin")
    _add(os.getenv("MCP_VIEWER_KEY"), "viewer", "viewer")

    expiry_days = int(gateway.get("break_glass_expiry_days", DEFAULT_BREAK_GLASS_EXPIRY_DAYS))
    dropped = 0
    resolver = None
    if any(isinstance(e, dict) and e.get("break_glass") for e in gateway.get("rbac", []) or []):
        from device_mcp_gateway.credentials import build_resolver

        resolver = build_resolver(cfg)

    for entry in gateway.get("rbac", []) or []:
        role = entry.get("role", "viewer")
        if not entry.get("break_glass"):
            _add(entry.get("key"), role, entry.get("name") or role)
            continue

        # ── ADR-0023: a flagged entry is held to two rules, both fatal ──────────────────
        #
        # 1. `name` is mandatory. Without it the loop above falls back to the ROLE, so two
        #    people holding two different break-glass credentials would both audit as
        #    `key:admin` — the shared-anonymous-credential problem this ADR exists to close,
        #    reappearing through an omitted field rather than a shared key. It is precisely
        #    the kind of gap that looks like nothing in review.
        name = entry.get("name")
        if not name or not str(name).strip():
            raise BreakGlassConfigError(
                "a gateway.rbac entry has break_glass: true and no name. Refusing to start — "
                "an unnamed flagged entry would audit as 'key:<role>', which is indistinguishable "
                "from every other holder and defeats the attribution this flag exists for "
                "(ADR-0023 §2)."
            )
        name = str(name).strip()

        # 2. The key is a `secret://` REFERENCE, never a literal. `gateway.rbac[].key` as
        #    originally specified reads the value straight out of the config document, which
        #    fails ADR-0017 §4's "never in configuration" regardless of how the value was
        #    generated or delivered — the document still carries the credential.
        raw = entry.get("key")
        if not raw:
            raise BreakGlassConfigError(f"gateway.rbac[{name!r}] is break_glass and has no key.")
        if not str(raw).startswith("secret://"):
            raise BreakGlassConfigError(
                f"gateway.rbac[{name!r}] is break_glass but its key is a literal value. A flagged "
                "entry takes a secret:// reference resolved through the credential store "
                "(ADR-0023 §1) — a literal in the config document fails 'never in configuration' "
                "however the value was generated."
            )
        # 3. A real lifetime (§3). `issued` is mandatory for the same reason `name` is.
        remaining = _break_glass_days_remaining(entry, name, expiry_days, today=date.today())

        # **An expired credential stops working; it does NOT stop the gateway.** The ADR asks
        # for a real cutoff rather than indefinite validity, and says nothing about startup —
        # so the choice is ours, and only one direction is defensible. Refusing to boot on an
        # expired break-glass entry converts a credential-hygiene lapse into an outage of the
        # mechanism that exists for outages: the operator reaching for break-glass during an
        # IdP failure would find the gateway itself refusing to start. So the key is dropped,
        # loudly, and everything else keeps serving.
        if remaining <= 0:
            logger.error(
                f"Break-glass credential '{name}' EXPIRED {-remaining} day(s) ago and has been "
                f"DROPPED — it will not authenticate. Reissue it: generate a new key, write it "
                f"to its secret:// location, and set issued to today. If this is the only "
                f"break-glass entry and OIDC is unavailable, nobody can reach this gateway."
            )
            dropped += 1
            continue
        if remaining <= _BREAK_GLASS_WARN_DAYS[1]:
            logger.warning(
                f"Break-glass credential '{name}' expires in {remaining} day(s). Reissue it now "
                "— once it lapses it stops authenticating, and that is discovered during the "
                "next incident rather than before it."
            )
        elif remaining <= _BREAK_GLASS_WARN_DAYS[0]:
            logger.warning(f"Break-glass credential '{name}' expires in {remaining} day(s); schedule a reissue.")

        _add(_resolve_break_glass_key(str(raw), resolver, name), role, name, break_glass=True)

    # **`enabled` tracks whether keys were CONFIGURED, not whether they survived.** An expired
    # break-glass entry is dropped from `keys` above, and if it was the only key configured
    # then `len(keys) == 0` — which previously meant "no auth configured anywhere" and served
    # every request as ANONYMOUS with full access. A credential lapsing must produce a 401,
    # never an open gateway: configured-but-expired and never-configured are opposite states
    # that happened to produce the same count.
    enabled = len(keys) > 0 or dropped > 0
    if enabled:
        flagged = _break_glass_entries(cfg)
        if not keys:
            logger.error(
                f"Every configured API key has expired ({dropped} break-glass entry/entries "
                "dropped). Auth stays ENABLED — every request will now be refused with 401 "
                "rather than served anonymously — but nothing can authenticate until a key is "
                "reissued."
            )
        logger.info(
            f"Gateway static-key auth: {len(keys)} API key(s) configured"
            + (f"; {len(flagged)} break-glass ({', '.join(flagged)})" if flagged else "")
        )
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
