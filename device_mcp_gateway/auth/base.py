# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Authentication module base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


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

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize auth config for persistence (includes secrets)."""
        ...

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> "AbstractAuth":
        """Reconstruct an auth handler from a persisted dict."""
        ...
