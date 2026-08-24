# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""OAuth 2.0 token-endpoint flows for outbound device auth.

Supports the non-interactive grants a gateway can run unattended (F-42):
``client_credentials`` (default), ``password``, and ``refresh_token``. Client
credentials go in the request body by default or as HTTP Basic (``auth_style``),
and ``audience`` / ``extra_params`` cover provider-specific knobs (Auth0
audience, RFC 8707 ``resource``, …).

Out of scope by design: the ``authorization_code`` grant (needs an interactive
redirect/user-consent, impossible for an unattended gateway) and ``jwt-bearer``
assertions (need per-device signing-key management) — documented in
docs/device-auth.md.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
from loguru import logger

from device_mcp_gateway.security.url_policy import (
    build_guarded_client,
    resolve_allow_private,
    resolve_allowed_ports,
)

from device_mcp_gateway.credentials.resolver import CredentialRef

from .base import AbstractAuth, CredentialNotBound, CredentialsChangedHook, exclusive_secret

_BODY_GRANTS = ("client_credentials", "password", "refresh_token")


@dataclass
class OAuth2Auth(AbstractAuth):
    """OAuth2 token-endpoint auth with automatic refresh."""

    token_endpoint: str
    client_id: str
    # Optional since ADR-0018 §1: supply this **or** `client_secret_ref`, never both and never
    # neither. It stays first for positional compatibility with every existing call site.
    client_secret: str | None = None
    scopes: list[str] | None = None
    refresh_before_expiry: int = 300
    grant_type: str = "client_credentials"
    auth_style: str = "request_body"  # request_body | basic
    audience: str | None = None
    username: str | None = None
    password: str | None = None
    refresh_token: str | None = None
    extra_params: dict[str, str] | None = None
    # ADR-0018 §1, the by-reference forms. Two named fields rather than one shared
    # `credential_ref`, because these are two independently-provisioned, independently-rotated
    # secrets; see `AbstractAuth.credential_refs`.
    #
    # There is deliberately no `refresh_token_ref`. That credential is gateway-minted (§1a) —
    # the gateway is the only party present when the provider rotates it, so there is nobody
    # else to write it and a reference model cannot describe it. It stays encrypted at rest.
    client_secret_ref: str | None = None
    password_ref: str | None = None

    def __post_init__(self):
        if self.grant_type not in _BODY_GRANTS:
            raise ValueError(f"grant_type must be one of {_BODY_GRANTS}, got {self.grant_type!r}")
        # Checked here rather than at the route, so every construction path — registration, a
        # restore, a worker rehydrating from the registry — gets the same answer. The same
        # reasoning as ApiKeyAuth's, and the same helper.
        exclusive_secret(
            self.client_secret, self.client_secret_ref, field="client_secret", ref_field="client_secret_ref"
        )
        # Only for the grant that actually sends one. A `client_credentials` device carries no
        # password, and demanding one of `password`/`password_ref` there would refuse a
        # perfectly ordinary registration.
        if self.grant_type == "password":
            exclusive_secret(self.password, self.password_ref, field="password", ref_field="password_ref")
        elif self.password_ref is not None:
            raise ValueError(
                f"password_ref is only meaningful for grant_type=password, not {self.grant_type!r}. "
                "A reference that is never resolved looks exactly like one that is."
            )
        for raw in (self.client_secret_ref, self.password_ref):
            if raw is not None:
                # Parsed at construction so a malformed reference is a registration error, not
                # a dispatch-time surprise on a device that looked fine when it was added.
                CredentialRef.parse(raw)
        if self.auth_style not in ("request_body", "basic"):
            raise ValueError(f"auth_style must be 'request_body' or 'basic', got {self.auth_style!r}")
        self._access_token: str | None = None
        self._token_expiry: float = 0.0
        self._scopes = self.scopes or ["read"]
        self._lock: asyncio.Lock = asyncio.Lock()
        # Egress posture for the token fetch. token_endpoint is validated at register/PUT,
        # but a DNS-rebind between then and the fetch would otherwise POST client_secret to
        # a rebound internal/metadata host — so the fetch goes through the SSRF guard too.
        # Default to the env override; the owning pod overrides with the resolved config
        # value via configure_egress() at wire-up.
        self._allow_private = resolve_allow_private({})
        self._allowed_ports = resolve_allowed_ports({})
        # Set by the owning pod via on_credentials_changed() so a rotated refresh token
        # reaches durable storage. None means nobody is persisting us (tests, ad-hoc use).
        self._credentials_changed: CredentialsChangedHook | None = None
        # Set by the owning pod via configure_credentials() at wire-up (ADR-0018 §2).
        self._resolver: Any | None = None

    def configure_egress(self, *, allow_private: bool, allowed_ports: set[int] | None = None) -> None:
        self._allow_private = allow_private
        self._allowed_ports = allowed_ports

    def on_credentials_changed(self, hook: CredentialsChangedHook) -> None:
        self._credentials_changed = hook

    def credential_refs(self) -> dict[str, str]:
        refs = {}
        if self.client_secret_ref:
            refs["client_secret_ref"] = self.client_secret_ref
        if self.password_ref:
            refs["password_ref"] = self.password_ref
        return refs

    def configure_credentials(self, resolver: Any | None) -> None:
        self._resolver = resolver

    async def bind(self, resolver: Any) -> None:
        """Resolve this handler's references for one token exchange.

        The resolved values live on the instance and are never written back: ``to_dict``
        re-emits the reference, not the material, so an update after a bind cannot quietly
        put the secret back in the registry.

        ``ReferenceInvalid`` and ``StoreUnavailable`` propagate unchanged — ADR-0018 §7's
        whole point is that the caller can tell a bad reference from a store outage.
        """
        if self.client_secret_ref:
            self.client_secret = await resolver.resolve(CredentialRef.parse(self.client_secret_ref))
        if self.password_ref:
            self.password = await resolver.resolve(CredentialRef.parse(self.password_ref))

    async def _ensure_bound(self) -> None:
        """Resolve before a token fetch, mirroring ``ApiKeyAuth._ensure_bound``.

        The failure modes are named apart for the same reason they are there: "this deployment
        has no resolver" and "the store said no" send an operator to different systems.
        """
        if not self.credential_refs():
            return
        resolver = getattr(self, "_resolver", None)
        if resolver is not None:
            await self.bind(resolver)
            return
        missing = [field for field, _ in self.credential_refs().items()]
        if self.client_secret is None or (self.grant_type == "password" and self.password is None):
            raise CredentialNotBound(
                f"device credential(s) {missing} have not been resolved: this handler was never "
                "given a credential resolver. Either the deployment has none configured "
                "(gateway.credentials.root / MCP_CREDENTIAL_ROOT), or this dispatch path predates "
                "the ADR-0018 wiring — which is what a replica mid-rolling-restart looks like."
            )

    async def ensure_token(self) -> None:
        async with self._lock:
            if self._access_token and time.time() < self._token_expiry - self.refresh_before_expiry:
                return
            # Inside the cached-token check on purpose: a live access token means the secret
            # was already good, and re-reading the store on every dispatch to prove it again
            # would make the token cache pointless and the store a per-request dependency.
            await self._ensure_bound()
            await self._fetch_token()

    def _bound(self, value: str | None, field: str) -> str:
        """The value, or a fail-closed error naming which secret was never resolved.

        Reached only if a caller builds a token request without going through
        ``ensure_token``. Raising beats sending ``"None"`` as a client secret, which the
        provider answers with a 401 that reads as a wrong credential and sends the operator
        to rotate a secret that was never the problem — the same reasoning as
        ``ApiKeyAuth._value``.
        """
        if value is None:
            raise CredentialNotBound(
                f"oauth2 {field} is unresolved for this handler; the dispatch path must bind "
                "the credential reference before building a token request"
            )
        return value

    def _build_request(self) -> tuple[dict[str, str], httpx.BasicAuth | None]:
        """Token-request body + optional HTTP Basic auth, per grant and auth_style."""
        data: dict[str, str] = {"grant_type": self.grant_type, "scope": " ".join(self._scopes)}
        if self.grant_type == "password":
            data["username"] = self.username or ""
            data["password"] = self._bound(self.password, "password")
        elif self.grant_type == "refresh_token":
            data["refresh_token"] = self.refresh_token or ""
        if self.audience:
            data["audience"] = self.audience
        if self.extra_params:
            data.update(self.extra_params)

        if self.auth_style == "basic":
            return data, httpx.BasicAuth(self.client_id, self._bound(self.client_secret, "client_secret"))
        # request_body: client creds travel in the form body.
        data["client_id"] = self.client_id
        data["client_secret"] = self._bound(self.client_secret, "client_secret")
        return data, None

    async def _fetch_token(self) -> None:
        data, basic = self._build_request()
        post_kwargs: dict[str, Any] = {"data": data}
        if basic is not None:
            post_kwargs["auth"] = basic
        # SSRF-guarded: validate_target_url runs on the token POST and every redirect
        # hop, so client_secret can't be steered to a private/loopback/metadata address.
        rotated = False
        async with build_guarded_client(
            allow_private=self._allow_private, allowed_ports=self._allowed_ports, timeout=10
        ) as client:
            try:
                resp = await client.post(self.token_endpoint, **post_kwargs)
                resp.raise_for_status()
                tokens = resp.json()
                self._access_token = tokens.get("access_token")
                # A rotated refresh token (if the provider returns one) replaces ours, and
                # must be written back to storage — see _persist_rotation below.
                new_refresh = tokens.get("refresh_token")
                if new_refresh and new_refresh != self.refresh_token:
                    self.refresh_token = new_refresh
                    rotated = True
                expires_in = int(tokens.get("expires_in", 3600))
                self._token_expiry = time.time() + expires_in
                logger.info("OAuth2 token retrieved successfully")
            except Exception as e:
                logger.error(f"OAuth2 token fetch failed: {e}")
                raise
        if rotated:
            await self._persist_rotation()

    async def _persist_rotation(self) -> None:
        """Push a rotated refresh token back to durable storage.

        Providers with refresh-token rotation (Google, Okta, Auth0 with rotation on,
        anything following OAuth 2.1) invalidate the old token the first time it is
        redeemed. Keeping the replacement only in memory means the stored credential is
        already dead: the pod runs fine until it restarts or is rebalanced onto another
        worker, then reloads the invalidated token and can never authenticate again —
        and at providers that treat a replayed refresh token as theft, redeeming the
        stale one can revoke the whole grant family.

        Best-effort by design: a storage failure is logged, never raised. The token fetch
        itself succeeded and the in-memory handler is usable, so failing the caller's tool
        call here would turn a durability problem into an outage.
        """
        hook = self._credentials_changed
        if hook is None:
            return
        try:
            await hook(self)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                f"OAuth2 refresh token rotated but could not be persisted ({exc}); the stored "
                "credential is now stale and this device may fail to authenticate after a restart"
            )

    async def get_headers(self) -> dict[str, str]:
        await self.ensure_token()
        return {"Authorization": f"Bearer {self._access_token}"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "oauth2",
            "token_endpoint": self.token_endpoint,
            "client_id": self.client_id,
            # A by-reference handler serialises its REFERENCE and not the material it may have
            # resolved a moment ago. Emitting a bound value would write the secret back into
            # the registry on the next update, quietly undoing ADR-0018 for that device — the
            # same trap ApiKeyAuth.to_dict guards against.
            "client_secret": None if self.client_secret_ref else self.client_secret,
            "scopes": self._scopes,
            "grant_type": self.grant_type,
            "auth_style": self.auth_style,
            "audience": self.audience,
            "username": self.username,
            "password": None if self.password_ref else self.password,
            "refresh_token": self.refresh_token,
            "extra_params": self.extra_params,
            "client_secret_ref": self.client_secret_ref,
            "password_ref": self.password_ref,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OAuth2Auth":
        return cls(
            token_endpoint=data["token_endpoint"],
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            scopes=data.get("scopes", ["read"]),
            grant_type=data.get("grant_type", "client_credentials"),
            auth_style=data.get("auth_style", "request_body"),
            audience=data.get("audience"),
            username=data.get("username"),
            password=data.get("password"),
            refresh_token=data.get("refresh_token"),
            extra_params=data.get("extra_params"),
            client_secret_ref=data.get("client_secret_ref"),
            password_ref=data.get("password_ref"),
        )
