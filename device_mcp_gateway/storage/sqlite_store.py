"""SQLite-backed device store using aiosqlite."""

from __future__ import annotations

import json
from typing import Any, Optional

import aiosqlite
from loguru import logger

from .base import AbstractDeviceStore

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS devices (
    hostname       TEXT PRIMARY KEY,
    base_url       TEXT NOT NULL,
    spec_url       TEXT,
    transport      TEXT NOT NULL DEFAULT 'sse',
    auth_type      TEXT,
    auth_config    TEXT,
    rate_limit_rps REAL
)
"""


class SqliteDeviceStore(AbstractDeviceStore):
    """Persists device registrations in a local SQLite database."""

    def __init__(self, db_path: str = "./devices.db", fernet: Optional[Any] = None) -> None:
        self._db_path = db_path
        self._fernet = fernet  # cryptography.fernet.Fernet instance, or None

    def _encrypt(self, plaintext: str) -> str:
        if self._fernet:
            return self._fernet.encrypt(plaintext.encode()).decode()
        return plaintext

    def _decrypt(self, stored: str) -> str:
        if self._fernet:
            try:
                return self._fernet.decrypt(stored.encode()).decode()
            except Exception:
                logger.warning(
                    "auth_config decryption failed — record may be unencrypted plaintext; "
                    "re-register the device to encrypt it"
                )
                return stored
        return stored

    async def initialize(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(_CREATE_TABLE)
            # Migration: add rate_limit_rps column for databases created before this version.
            try:
                await db.execute("ALTER TABLE devices ADD COLUMN rate_limit_rps REAL")
            except Exception:
                pass  # column already exists
            await db.commit()
        logger.info(f"SQLite device store initialised at {self._db_path}")

    async def save(self, hostname: str, record: dict[str, Any]) -> None:
        auth_config = record.get("auth_config")
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO devices
                    (hostname, base_url, spec_url, transport, auth_type, auth_config, rate_limit_rps)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hostname,
                    record["base_url"],
                    record.get("spec_url"),
                    record.get("transport", "sse"),
                    record.get("auth_type"),
                    self._encrypt(json.dumps(auth_config)) if auth_config else None,
                    record.get("rate_limit_rps"),
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
                "SELECT hostname, base_url, spec_url, transport, auth_type, auth_config, rate_limit_rps FROM devices"
            ) as cursor:
                rows = await cursor.fetchall()
        result = []
        for row in rows:
            auth_config = None
            if row["auth_config"]:
                try:
                    auth_config = json.loads(self._decrypt(row["auth_config"]))
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
                    "rate_limit_rps": row["rate_limit_rps"],
                }
            )
        return result
