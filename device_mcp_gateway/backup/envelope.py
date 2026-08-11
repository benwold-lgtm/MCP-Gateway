# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The backup archive format: envelope, canary, and passphrase key derivation (ADR-0011).

One module owns the format so the writer (``backup.export``) and the reader
(``backup.restore``) cannot drift apart. A format defined in two places fails at the worst
possible moment — when an operator is trying to open an archive during an incident.

Two archive kinds, and the difference is *what can open them*:

- ``ciphertext`` — credentials stay encrypted exactly as stored, under the exporting
  stack's ``MCP_SECRET_KEY``. The default. Worthless to someone who steals only the
  archive, which is the entire point.
- ``portable`` — credentials re-encrypted to a caller-supplied passphrase via Argon2id.
  Key-independent by design: it restores into a stack whose ``MCP_SECRET_KEY`` differs, or
  whose key is gone. That also makes it a complete set of live credentials behind one
  passphrase, hence its own scope, a strength floor, and its own audit action.

**Neither kind ever contains ``MCP_SECRET_KEY``.**

The canary
----------
Every envelope carries a known plaintext encrypted under the same key or passphrase as the
archive body. Without it the fail-closed preflight is not total: an archive whose devices
all use ``auth_type: none`` contains no credential ciphertext at all, so a "decrypt
everything" check would pass while proving nothing — and the operator would learn the key
was wrong only after the restore had written a fleet it could not authenticate.

Argon2id parameters live in the envelope
----------------------------------------
The reader derives using the parameters the *archive* declares, never today's config.
Raising the cost later therefore hardens new archives without orphaning existing ones.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

ARCHIVE_FORMAT = "device-mcp-gateway/backup"
ARCHIVE_VERSION = 1

KIND_CIPHERTEXT = "ciphertext"
KIND_PORTABLE = "portable"
ARCHIVE_KINDS = (KIND_CIPHERTEXT, KIND_PORTABLE)

# The canary plaintext. Fixed and public — its secrecy is irrelevant; what matters is that
# a reader who can decrypt it holds the right key, and a reader who cannot knows so before
# a single device is written.
CANARY_PLAINTEXT = b"device-mcp-gateway/backup/canary/v1"

_SALT_BYTES = 16
_DERIVED_KEY_BYTES = 32


class BackupError(Exception):
    """A backup archive could not be built, parsed, or opened."""


class PassphraseTooWeak(BackupError):
    """A portable export was asked for with a passphrase below the configured floor."""


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters plus the per-archive salt.

    Carried in the envelope so an archive is self-describing. ``from_envelope`` is the
    only way a reader should obtain these — deriving with today's configured cost against
    an archive made under a different one silently produces the wrong key, which is
    indistinguishable from a wrong passphrase.
    """

    memory_cost_kib: int
    iterations: int
    lanes: int
    salt: bytes

    @classmethod
    def generate(cls, *, memory_cost_kib: int, iterations: int, lanes: int) -> "Argon2Params":
        return cls(
            memory_cost_kib=memory_cost_kib,
            iterations=iterations,
            lanes=lanes,
            salt=os.urandom(_SALT_BYTES),
        )

    def to_envelope(self, *, passphrase_min_length: int) -> dict[str, Any]:
        return {
            "algorithm": "argon2id",
            "memory_cost_kib": self.memory_cost_kib,
            "iterations": self.iterations,
            "lanes": self.lanes,
            "salt": base64.b64encode(self.salt).decode(),
            "passphrase_min_length": passphrase_min_length,
        }

    @classmethod
    def from_envelope(cls, kdf: dict[str, Any]) -> "Argon2Params":
        algorithm = kdf.get("algorithm")
        if algorithm != "argon2id":
            raise BackupError(f"unsupported key-derivation algorithm in archive: {algorithm!r} (expected 'argon2id')")
        try:
            return cls(
                memory_cost_kib=int(kdf["memory_cost_kib"]),
                iterations=int(kdf["iterations"]),
                lanes=int(kdf["lanes"]),
                salt=base64.b64decode(kdf["salt"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupError(f"archive key-derivation parameters are malformed: {exc}") from exc


def fernet_for_passphrase(passphrase: str, params: Argon2Params) -> Any:
    """Derive a Fernet from a passphrase using the given Argon2id parameters.

    Called **once per archive**, not once per credential: the whole archive body is sealed
    under one derived key, so the cost is paid a single time on export and a single time
    on restore.
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    kdf = Argon2id(
        salt=params.salt,
        length=_DERIVED_KEY_BYTES,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost_kib,
    )
    derived = kdf.derive(passphrase.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


def check_passphrase(passphrase: str | None, *, minimum: int) -> str:
    """Enforce the passphrase floor at export. Raises :class:`PassphraseTooWeak`."""
    if not passphrase:
        raise PassphraseTooWeak("a portable export requires a passphrase")
    if len(passphrase) < minimum:
        raise PassphraseTooWeak(
            f"passphrase must be at least {minimum} characters (got {len(passphrase)}); "
            "this archive carries every device credential in the stack"
        )
    return passphrase


def build_envelope(
    *,
    kind: str,
    gateway_version: str,
    mode: str,
    canary: str,
    counts: dict[str, int],
    kdf: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The archive header. Body sections are added by the caller."""
    if kind not in ARCHIVE_KINDS:
        raise BackupError(f"unknown archive kind {kind!r} (expected one of {', '.join(ARCHIVE_KINDS)})")
    envelope: dict[str, Any] = {
        "format": ARCHIVE_FORMAT,
        "version": ARCHIVE_VERSION,
        "kind": kind,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "gateway_version": gateway_version,
        "mode": mode,
        "canary": canary,
        "counts": counts,
    }
    if kdf is not None:
        envelope["kdf"] = kdf
    return envelope


def parse_archive(raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Load an archive and check its framing before anything reads its body.

    Shape errors are named here rather than surfacing as a ``KeyError`` three layers
    down while a restore is half-considered.
    """
    if isinstance(raw, dict):
        archive = raw
    else:
        try:
            archive = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise BackupError(f"archive is not valid JSON: {exc}") from exc
    if not isinstance(archive, dict):
        raise BackupError("archive must be a JSON object")
    if archive.get("format") != ARCHIVE_FORMAT:
        raise BackupError(f"not a {ARCHIVE_FORMAT} archive (format={archive.get('format')!r})")
    version = archive.get("version")
    if version != ARCHIVE_VERSION:
        raise BackupError(f"unsupported archive version {version!r} (this gateway reads version {ARCHIVE_VERSION})")
    if archive.get("kind") not in ARCHIVE_KINDS:
        raise BackupError(f"unknown archive kind {archive.get('kind')!r}")
    if not archive.get("canary"):
        raise BackupError("archive has no canary token — refusing to trust a preflight that cannot be made total")
    return archive


def seal_canary(fernet_or_codec: Any) -> str:
    """Encrypt the canary plaintext under whatever seals this archive's credentials.

    Accepts either a ``Fernet`` (portable) or a :class:`~device_mcp_gateway.shared.crypto.
    CredentialCodec` (ciphertext), since both are "the thing that encrypts this archive" —
    the canary must travel under exactly the same key as the body or it proves nothing
    about it.
    """
    encrypt = getattr(fernet_or_codec, "encrypt", None)
    if encrypt is None:  # pragma: no cover — programming error, not an operator one
        raise BackupError("cannot seal canary: object has no encrypt()")
    sealed = encrypt(CANARY_PLAINTEXT.decode() if _wants_str(fernet_or_codec) else CANARY_PLAINTEXT)
    return sealed if isinstance(sealed, str) else sealed.decode()


def verify_canary(archive: dict[str, Any], fernet_or_codec: Any) -> None:
    """Decrypt-test the canary. Raises :class:`BackupError` naming the likely cause.

    This is the first gate of the restore preflight and the one that makes it total.
    """
    token = archive.get("canary", "")
    decrypt = getattr(fernet_or_codec, "decrypt", None)
    if decrypt is None:  # pragma: no cover — programming error
        raise BackupError("cannot verify canary: object has no decrypt()")
    try:
        plaintext = decrypt(token if _wants_str(fernet_or_codec) else token.encode())
    except Exception as exc:
        raise BackupError(_canary_failure_hint(archive)) from exc
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if plaintext != CANARY_PLAINTEXT:
        raise BackupError(_canary_failure_hint(archive))


def _canary_failure_hint(archive: dict[str, Any]) -> str:
    """Name the expected failure. A bare ``InvalidToken`` sends an operator hunting for a
    corrupt file when the real answer is almost always "wrong key" or "wrong passphrase"."""
    if archive.get("kind") == KIND_PORTABLE:
        return "could not open this portable archive — the passphrase is wrong (or the archive is corrupt)"
    return (
        "could not open this ciphertext archive — it was encrypted under a different "
        "MCP_SECRET_KEY than this stack's (or the archive is corrupt). Restore it into a "
        "stack sharing that key, or use a portable archive to cross key generations."
    )


def _wants_str(obj: Any) -> bool:
    """True for our CredentialCodec (str in/str out), False for a raw Fernet (bytes)."""
    from device_mcp_gateway.shared.crypto import CredentialCodec

    return isinstance(obj, CredentialCodec)
