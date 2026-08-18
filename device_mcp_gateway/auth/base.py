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


class CredentialNotBound(RuntimeError):
    """A by-reference handler was used before its material was resolved (ADR-0018 §1).

    Raised rather than sending an empty or placeholder credential upstream. A device that
    authenticates with the string ``None`` fails at the upstream with a 401, which reads as
    "wrong password" and sends the operator to check their secret store — when what actually
    happened is that the gateway skipped a resolution step.
    """


def exclusive_secret(literal: Any, ref: Any, *, field: str) -> None:
    """Enforce ADR-0018's migration rule: a secret is inline **or** by reference, never both.

    Both is refused rather than resolved by precedence. A record carrying an inline value and
    a reference has two answers to "what is this device's credential", and any precedence rule
    makes the losing one invisible — so a reference that silently never took effect looks
    exactly like one that did. Neither is refused for the same reason: it is a device that
    cannot authenticate, and finding that out at registration beats finding out at dispatch.
    """
    if literal is not None and ref is not None:
        raise ValueError(
            f"{field} and {field}_ref are mutually exclusive (ADR-0018): a device holds its "
            "secret inline or by reference, never both."
        )
    if literal is None and ref is None:
        raise ValueError(f"one of {field} or {field}_ref is required")


class AbstractAuth(ABC):
    """Base class for authentication handlers."""

    #: The credential reference this handler resolves before use, or ``None`` when the
    #: secret is inline. Read by the dispatch path; handlers that hold no secret leave it
    #: ``None`` and are unaffected by ADR-0018.
    credential_ref: str | None = None

    async def bind(self, resolver: Any) -> None:
        """Resolve this handler's reference into usable material for one dispatch.

        No-op when the secret is inline. Implementations MUST NOT persist what they resolve:
        the material lives for the request, which is the line ADR-0018 §1 draws between a
        cache and a durable copy.

        **This seam is for operator-provisioned secrets only** (ADR-0018 §1a). A credential the
        gateway mints and rotates itself — an OAuth2 refresh token — has no external writer and
        cannot be held by reference; it stays encrypted at rest. Do not extend this to one
        without reading §1a, which explains why the boundary is where it is.
        """
        return None

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
