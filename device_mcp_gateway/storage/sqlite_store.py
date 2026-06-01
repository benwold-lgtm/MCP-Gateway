"""SQLite-backed device store using aiosqlite."""

from __future__ import annotations

import json
from typing import Any

import aiosqlite
from loguru import logger

from .base import AbstractDeviceStore

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS devices (
    hostname    TEXT PRIMARY KEY,
    base_url    TEXT NOT NULL,
    spec_url    TEXT,
    transport   TEXT NOT NULL DEFAULT 'sse',
    auth_type   TEXT,
    auth_config TEXT
)
"""


class SqliteDeviceStore(AbstractDeviceStore):
    """Persists device registrations in a local SQLite database."""

    def __init__(self, db_path: str = "./devices.db"):
        self._db_path = db_path

    async def initialize(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(_CREATE_TABLE)
            await db.commit()
        logger.info(f"SQLite device store initialised at {self._db_path}")

    async def save(self, hostname: str, record: dict[str, Any]) -> None:
        auth_config = record.get("auth_config")
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO devices
                    (hostname, base_url, spec_url, transport, auth_type, auth_config)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    hostname,
                    record["base_url"],
                    record.get("spec_url"),
                    record.get("transport", "sse"),
                    record.get("auth_type"),
                    json.dumps(auth_config) if auth_config else None,
                ),
            )
            await db.commit()

    async def delete(self, hostname: str) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("DELETE FROM devices WHERE hostname = ?", (hostname,))
            await db.commit()

    async def load_all(self) -> list[dict[str, Any]]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT hostname, base_url, spec_url, transport, auth_type, auth_config FROM devices"
            ) as cursor:
                rows = await cursor.fetchall()
        result = []
        for row in rows:
            auth_config = None
            if row["auth_config"]:
                try:
                    auth_config = json.loads(row["auth_config"])
                except Exception:
                    logger.warning(f"Could not parse auth_config for {row['hostname']}")
            result.append(
                {
                    "hostname": row["hostname"],
                    "base_url": row["base_url"],
                    "spec_url": row["spec_url"],
                    "transport": row["transport"],
                    "auth_type": row["auth_type"],
                    "auth_config": auth_config,
                }
            )
        return result
