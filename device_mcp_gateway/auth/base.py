"""Authentication module base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from loguru import logger


class AbstractAuth(ABC):
    """Base class for authentication handlers."""

    @abstractmethod
    async def get_headers(self) -> dict[str, str]:
        """Return HTTP headers needed for authentication."""
        ...

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize auth config for persistence (includes secrets)."""
        ...

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> "AbstractAuth":
        """Reconstruct an auth handler from a persisted dict."""
        ...
