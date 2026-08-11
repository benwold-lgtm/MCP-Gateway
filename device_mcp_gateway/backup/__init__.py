# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Backup and restore for the gateway's durable state (ADR-0011).

``envelope`` owns the archive format — the canary, the Argon2id key derivation, and the
sealing/opening of an archive under either a Fernet key or a passphrase. ``export`` builds
one from a live registry. The reader and the writer share ``envelope`` deliberately: a
format defined twice is a format that drifts, and the failure would surface at the moment
an operator most needs the archive to open.
"""

from device_mcp_gateway.backup.envelope import (
    ARCHIVE_FORMAT,
    ARCHIVE_VERSION,
    Argon2Params,
    BackupError,
    KIND_CIPHERTEXT,
    KIND_PORTABLE,
    PassphraseTooWeak,
    build_envelope,
    fernet_for_passphrase,
    verify_canary,
)

__all__ = [
    "ARCHIVE_FORMAT",
    "ARCHIVE_VERSION",
    "Argon2Params",
    "BackupError",
    "KIND_CIPHERTEXT",
    "KIND_PORTABLE",
    "PassphraseTooWeak",
    "build_envelope",
    "fernet_for_passphrase",
    "verify_canary",
]
