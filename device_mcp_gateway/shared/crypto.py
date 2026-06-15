# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Shared credential-encryption codec.

A single place that turns a Fernet key (or keys) into encrypt/decrypt operations
for device credential blobs. Used on every persistence path:

  - SQLite store (embedded mode)
  - Redis registry write (gateway, distributed mode)
  - Redis registry read (worker, distributed mode)

Before this existed, encryption lived only in the SQLite store, so distributed
mode wrote credentials to Redis in plaintext. Centralising it here closes that
gap and keeps the key-handling logic in one place.

Key rotation (F-34)
-------------------
The codec accepts *multiple* keys (Fernet's ``MultiFernet``). The first key is
primary — it encrypts all new writes; every key can decrypt. This is what makes
rotation zero-downtime:

  1. Generate a new key. Deploy with ``secret_keys: [<new>, <old>]`` (new first).
     Running gateways/workers now encrypt with <new> and still decrypt <old>.
  2. Run ``device-mcp-rotate-secrets`` to re-encrypt every stored credential
     under <new> (``codec.rotate`` decrypts with any key, re-encrypts with the
     primary).
  3. Once the pass is done, deploy with ``secret_keys: [<new>]`` and retire <old>.

A single key is the common case and behaves exactly as before.
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional


def _coerce_keys(raw: str | bytes | list | tuple | None) -> list[str]:
    """Normalise a key spec into an ordered list of non-empty key strings.

    Accepts a list/tuple of keys, or a single string/bytes that may itself hold
    several keys separated by commas or whitespace (so ``MCP_SECRET_KEY`` can
    carry "new,old" for a rotation window). Order is preserved; the first key is
    primary.
    """
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        items: list[Any] = list(raw)
    else:
        text = raw.decode() if isinstance(raw, bytes) else raw
        items = re.split(r"[,\s]+", text.strip())
    return [str(i).strip() for i in items if str(i).strip()]


class CredentialCodec:
    """Encrypts/decrypts credential strings with Fernet (one or more keys).

    When no key is configured the codec is *disabled* and passes values through
    unchanged — convenient for local/embedded development. Production
    (distributed) mode refuses to start without a key; see create_app() and
    worker_main().
    """

    def __init__(self, fernet: Optional[Any] = None) -> None:
        # May be a Fernet, a MultiFernet, or None (disabled). Both Fernet and
        # MultiFernet expose encrypt/decrypt; only MultiFernet exposes rotate, so
        # rotate() below handles the single-key case explicitly.
        self._fernet = fernet
        # The primary (encrypting) key on its own, used to tell whether a token is
        # already current — MultiFernet.rotate() always emits fresh ciphertext, so
        # output equality can't detect "already rotated". For a MultiFernet that is
        # its first key; for a bare Fernet it is the key itself.
        inner = getattr(fernet, "_fernets", None)  # MultiFernet exposes _fernets
        self._primary = inner[0] if inner else fernet

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    @property
    def fernet(self) -> Optional[Any]:
        return self._fernet

    @property
    def multi_key(self) -> bool:
        """True when more than one key is configured (a rotation is in progress)."""
        return hasattr(self._fernet, "rotate")

    @classmethod
    def from_secret(cls, secret_raw: str | bytes | list | tuple | None) -> "CredentialCodec":
        """Build a codec from one or more raw Fernet keys.

        Returns a disabled codec when no key is given. Raises ValueError when a
        key is present but malformed (surfaced loudly rather than silently
        falling back to plaintext). With two or more keys the first is primary
        (encrypts) and all keys decrypt.
        """
        keys = _coerce_keys(secret_raw)
        if not keys:
            return cls(None)
        from cryptography.fernet import Fernet, MultiFernet

        fernets = [Fernet(k.encode()) for k in keys]  # raises ValueError on a malformed key
        return cls(MultiFernet(fernets) if len(fernets) > 1 else fernets[0])

    @classmethod
    def from_config(cls, cfg: dict) -> "CredentialCodec":
        """Build a codec from MCP_SECRET_KEY / gateway.secret_keys / gateway.secret_key."""
        return cls.from_secret(secret_keys_from_config(cfg))

    def encrypt(self, plaintext: str) -> str:
        if self._fernet is None:
            return plaintext
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, stored: str) -> str:
        if self._fernet is None:
            return stored
        return self._fernet.decrypt(stored.encode()).decode()

    def is_current(self, token: str) -> bool:
        """True when ``token`` is already encrypted under the primary key.

        Lets a rotation pass skip values that are already current instead of
        needlessly rewriting them (and gives a meaningful unchanged count).
        """
        if self._primary is None:
            return True  # disabled codec — nothing to rotate
        from cryptography.fernet import InvalidToken

        try:
            self._primary.decrypt(token.encode())
            return True
        except InvalidToken:
            return False

    def rotate(self, token: str) -> str:
        """Re-encrypt a token under the primary key, decrypting with any key.

        Returns the token *unchanged* when the codec is disabled or the value is
        already encrypted under the primary key (so the pass is idempotent). For a
        multi-key codec a value encrypted with an older key comes back encrypted
        with the current primary key (via ``MultiFernet.rotate``). Raises
        ``cryptography.fernet.InvalidToken`` when no configured key can decrypt
        the value — callers should report and skip rather than drop the record.
        """
        if self._fernet is None or self.is_current(token):
            return token
        if hasattr(self._fernet, "rotate"):  # MultiFernet
            return self._fernet.rotate(token.encode()).decode()
        return self.encrypt(self.decrypt(token))


def secret_keys_from_config(cfg: dict) -> list[str]:
    """Resolve the ordered Fernet key list from the environment or config.

    Precedence: ``MCP_SECRET_KEY`` (may hold several comma/space-separated keys)
    wins entirely; otherwise ``gateway.secret_keys`` (a list); otherwise the
    legacy single ``gateway.secret_key``. The first key is primary.
    """
    env = os.getenv("MCP_SECRET_KEY")
    if env:
        return _coerce_keys(env)
    gw = cfg.get("gateway", {})
    if gw.get("secret_keys"):
        return _coerce_keys(gw.get("secret_keys"))
    return _coerce_keys(gw.get("secret_key"))


def secret_from_config(cfg: dict) -> str:
    """Back-compat: the primary Fernet key (first of the resolved list), or ""."""
    keys = secret_keys_from_config(cfg)
    return keys[0] if keys else ""
