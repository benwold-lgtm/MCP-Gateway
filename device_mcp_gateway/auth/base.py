# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Authentication module base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# Called when a handler mutates its own persisted credential material, with the handler
# itself as the argument. The owner (embedded registry / distributed worker) re-serialises
# and re-encrypts it. Async because every implementation writes to Redis or SQLite.
CredentialsChangedHook = Callable[["AbstractAuth"], Awaitable[None]]


@dataclass
class AuthMaterial:
    """Everything an auth handler contributes to an outbound request.

    Most handlers only set headers, but an API key can live in a query param or a
    cookie (F-43), so the seam carries all three. The pod applies these LAST —
    over any tool-supplied header/query value — so a tool argument can never
    override the device's credentials (Tier-0 F-25).
    """

    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


class AbstractAuth(ABC):
    """Base class for authentication handlers."""

    @abstractmethod
    async def get_headers(self) -> dict[str, str]:
        """Return HTTP headers needed for authentication."""
        ...

    async def apply(self) -> AuthMaterial:
        """Return the full auth material (headers + query params + cookies).

        Default is header-only (delegates to ``get_headers``); handlers that place
        credentials elsewhere — e.g. an API key in a query param or cookie —
        override this.
        """
        return AuthMaterial(headers=await self.get_headers())

    def configure_egress(self, *, allow_private: bool, allowed_ports: set[int] | None = None) -> None:
        """Adopt the gateway's SSRF egress policy for any outbound call this handler
        makes itself (e.g. an OAuth2 token fetch). No-op for handlers that don't make
        their own network calls. The owning pod calls this at wire-up so the handler's
        egress posture matches the configured ``allow_private`` / ``allowed_target_ports``
        settings (F-02, review item 9)."""
        return None

    def on_credentials_changed(self, hook: CredentialsChangedHook) -> None:
        """Register a callback for when this handler rotates its own stored credentials.

        No-op for handlers whose persisted material never changes at runtime (an API key
        is whatever the operator registered). ``OAuth2Auth`` overrides it: providers that
        rotate refresh tokens hand back a new one on every refresh, and without a
        write-back the stored token is dead the moment it is first used — the pod keeps
        working until it restarts, then can never authenticate again.

        The owning pod wires this at the same point it calls ``configure_egress``."""
        return None

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize auth config for persistence (includes secrets)."""
        ...

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> "AbstractAuth":
        """Reconstruct an auth handler from a persisted dict."""
        ...
