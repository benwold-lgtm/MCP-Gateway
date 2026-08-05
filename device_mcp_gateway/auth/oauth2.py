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

from .base import AbstractAuth, CredentialsChangedHook

_BODY_GRANTS = ("client_credentials", "password", "refresh_token")


@dataclass
class OAuth2Auth(AbstractAuth):
    """OAuth2 token-endpoint auth with automatic refresh."""

    token_endpoint: str
    client_id: str
    client_secret: str
    scopes: list[str] | None = None
    refresh_before_expiry: int = 300
    grant_type: str = "client_credentials"
    auth_style: str = "request_body"  # request_body | basic
    audience: str | None = None
    username: str | None = None
    password: str | None = None
    refresh_token: str | None = None
    extra_params: dict[str, str] | None = None

    def __post_init__(self):
        if self.grant_type not in _BODY_GRANTS:
            raise ValueError(f"grant_type must be one of {_BODY_GRANTS}, got {self.grant_type!r}")
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

    def configure_egress(self, *, allow_private: bool, allowed_ports: set[int] | None = None) -> None:
        self._allow_private = allow_private
        self._allowed_ports = allowed_ports

    def on_credentials_changed(self, hook: CredentialsChangedHook) -> None:
        self._credentials_changed = hook

    async def ensure_token(self) -> None:
        async with self._lock:
            if self._access_token and time.time() < self._token_expiry - self.refresh_before_expiry:
                return
            await self._fetch_token()

    def _build_request(self) -> tuple[dict[str, str], httpx.BasicAuth | None]:
        """Token-request body + optional HTTP Basic auth, per grant and auth_style."""
        data: dict[str, str] = {"grant_type": self.grant_type, "scope": " ".join(self._scopes)}
        if self.grant_type == "password":
            data["username"] = self.username or ""
            data["password"] = self.password or ""
        elif self.grant_type == "refresh_token":
            data["refresh_token"] = self.refresh_token or ""
        if self.audience:
            data["audience"] = self.audience
        if self.extra_params:
            data.update(self.extra_params)

        if self.auth_style == "basic":
            return data, httpx.BasicAuth(self.client_id, self.client_secret)
        # request_body: client creds travel in the form body.
        data["client_id"] = self.client_id
        data["client_secret"] = self.client_secret
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
            "client_secret": self.client_secret,
            "scopes": self._scopes,
            "grant_type": self.grant_type,
            "auth_style": self.auth_style,
            "audience": self.audience,
            "username": self.username,
            "password": self.password,
            "refresh_token": self.refresh_token,
            "extra_params": self.extra_params,
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
        )
