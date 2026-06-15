# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Credential key-rotation pass (F-34).

Re-encrypts every stored device credential under the codec's *primary* key,
decrypting each with whichever configured key still matches. Used during a
zero-downtime key rotation: deploy with ``secret_keys: [<new>, <old>]``, run this
pass, then retire ``<old>``.

Two storage paths mirror the two deployment modes:
  - ``rotate_sqlite_credentials`` — embedded mode (SQLite store)
  - ``rotate_redis_credentials``  — distributed mode (Redis registry backend)

Both operate on the raw ciphertext so a credential that no key can decrypt is
reported and left intact rather than silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.fernet import InvalidToken
from loguru import logger

if TYPE_CHECKING:  # avoid import cycles / heavy imports at module load
    from device_mcp_gateway.shared.crypto import CredentialCodec
    from device_mcp_gateway.shared.registry_backend import AbstractRegistryBackend
    from device_mcp_gateway.storage.sqlite_store import SqliteDeviceStore


@dataclass
class RotationResult:
    """Outcome of a rotation pass."""

    rotated: int = 0  # re-encrypted under the new primary key
    unchanged: int = 0  # already encrypted with the primary key
    failed: int = 0  # no configured key could decrypt — left untouched
    failed_hostnames: list[str] | None = None

    def __post_init__(self) -> None:
        if self.failed_hostnames is None:
            self.failed_hostnames = []

    @property
    def total(self) -> int:
        return self.rotated + self.unchanged + self.failed

    def summary(self) -> str:
        line = (
            f"{self.total} credential(s): {self.rotated} rotated, "
            f"{self.unchanged} already current, {self.failed} failed"
        )
        if self.failed_hostnames:
            line += f" (failed: {', '.join(self.failed_hostnames)})"
        return line


def _rotate_one(codec: "CredentialCodec", token: str, hostname: str, result: RotationResult) -> str | None:
    """Rotate a single token; update counters. Returns the new token or None."""
    try:
        new_token = codec.rotate(token)
    except InvalidToken:
        result.failed += 1
        assert result.failed_hostnames is not None
        result.failed_hostnames.append(hostname)
        logger.error(f"Credential rotation failed for {hostname}: no configured key can decrypt it — left untouched")
        return None
    if new_token == token:
        result.unchanged += 1
        return None
    result.rotated += 1
    return new_token


async def rotate_sqlite_credentials(store: "SqliteDeviceStore", codec: "CredentialCodec") -> RotationResult:
    """Re-encrypt SQLite-stored credentials under the codec's primary key."""
    result = RotationResult()
    for hostname, raw in await store.iter_raw_credentials():
        new_token = _rotate_one(codec, raw, hostname, result)
        if new_token is not None:
            await store.set_raw_credential(hostname, new_token)
            logger.info(f"Rotated credential for {hostname}")
    return result


async def rotate_redis_credentials(backend: "AbstractRegistryBackend", codec: "CredentialCodec") -> RotationResult:
    """Re-encrypt Redis-stored device credentials under the codec's primary key."""
    result = RotationResult()
    for hostname in await backend.list_hostnames():
        cfg = await backend.get_device(hostname)
        if cfg is None or not cfg.auth_config:
            continue
        new_token = _rotate_one(codec, cfg.auth_config, hostname, result)
        if new_token is not None:
            await backend.update_device_fields(hostname, auth_config=new_token)
            logger.info(f"Rotated credential for {hostname}")
    return result
