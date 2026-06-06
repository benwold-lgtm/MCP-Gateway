# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Shared credential-encryption codec.

A single place that turns a Fernet key into encrypt/decrypt operations for
device credential blobs. Used on every persistence path:

  - SQLite store (embedded mode)
  - Redis registry write (gateway, distributed mode)
  - Redis registry read (worker, distributed mode)

Before this existed, encryption lived only in the SQLite store, so distributed
mode wrote credentials to Redis in plaintext. Centralising it here closes that
gap and keeps the key-handling logic in one place.
"""

from __future__ import annotations

import os
from typing import Any, Optional


class CredentialCodec:
    """Encrypts/decrypts credential strings with Fernet.

    When no key is configured the codec is *disabled* and passes values through
    unchanged — convenient for local/embedded development. Production
    (distributed) mode refuses to start without a key; see create_app() and
    worker_main().
    """

    def __init__(self, fernet: Optional[Any] = None) -> None:
        self._fernet = fernet

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    @property
    def fernet(self) -> Optional[Any]:
        return self._fernet

    @classmethod
    def from_secret(cls, secret_raw: str | bytes | None) -> "CredentialCodec":
        """Build a codec from a raw Fernet key.

        Returns a disabled codec when the key is empty. Raises ValueError when a
        key is present but malformed (surfaced loudly rather than silently
        falling back to plaintext).
        """
        if not secret_raw:
            return cls(None)
        from cryptography.fernet import Fernet

        key = secret_raw.encode() if isinstance(secret_raw, str) else secret_raw
        return cls(Fernet(key))  # raises ValueError on a malformed key

    @classmethod
    def from_config(cls, cfg: dict) -> "CredentialCodec":
        """Build a codec from MCP_SECRET_KEY or gateway.secret_key."""
        return cls.from_secret(secret_from_config(cfg))

    def encrypt(self, plaintext: str) -> str:
        if self._fernet is None:
            return plaintext
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, stored: str) -> str:
        if self._fernet is None:
            return stored
        return self._fernet.decrypt(stored.encode()).decode()


def secret_from_config(cfg: dict) -> str:
    """Resolve the Fernet secret from the environment or config (env wins)."""
    return os.getenv("MCP_SECRET_KEY") or cfg.get("gateway", {}).get("secret_key") or ""
