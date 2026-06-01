"""Authentication module base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from loguru import logger


class AbstractAuth(ABC):
    """Base class for authentication handlers."""

    @abstractmethod
    def get_headers(self) -> dict[str, str]:
        """Return HTTP headers needed for authentication."""
        ...
