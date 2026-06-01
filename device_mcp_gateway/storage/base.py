"""Abstract interface for device registry persistence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AbstractDeviceStore(ABC):
    """Persist and retrieve registered device records."""

    @abstractmethod
    async def initialize(self) -> None:
        """Set up storage backend (create tables, open files, etc.)."""
        ...

    @abstractmethod
    async def save(self, hostname: str, record: dict[str, Any]) -> None:
        """Upsert a device record keyed by hostname."""
        ...

    @abstractmethod
    async def delete(self, hostname: str) -> None:
        """Remove a device record."""
        ...

    @abstractmethod
    async def load_all(self) -> list[dict[str, Any]]:
        """Return all persisted device records."""
        ...
