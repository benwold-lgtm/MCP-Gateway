# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Build a backup archive from a live registry (ADR-0011).

What goes in, and why the list is short
---------------------------------------
**Included** — the device registry and the governance record of how each device's tool
surface last changed (``device:{h}:tools_change``, deliberately un-TTL'd because it is the
one thing here with no other source of truth).

**Opt-in** — dead letters. Valuable mid-incident, unbounded noise otherwise.

**Excluded on purpose** — everything reconstructible or ephemeral: claims and leases,
worker membership, assignment and call streams, sessions, idempotency markers, rate-limit
counters, the TTL'd manifest cache. Restoring a stale claim or a half-consumed stream would
actively harm a fresh stack, so the omission is a feature, not a gap.

Per device the archive carries **registration inputs**, not runtime state. ``pod_active``,
``reachable``, ``last_check``, ``worker_id`` and ``spec_hash`` are all measurements of a
particular running stack and mean nothing in another one — restoring them would assert
facts about a fleet that has not been contacted yet, which is exactly the mistake F-66 was.
The restoring stack establishes them itself.

The credential field
--------------------
The archive's ``auth_config`` is always **ciphertext under whatever seals this archive** —
the stack's ``MCP_SECRET_KEY`` for a ciphertext archive, the passphrase-derived key for a
portable one. That invariant needs stating because the two modes do not store credentials
the same way:

- **Distributed** encrypts before writing to Redis (``Registry._register_distributed``).
- **Embedded** stores ``DeviceConfig.auth_config`` as **plaintext JSON** — encryption
  happens a layer lower, in the SQLite store.

So exporting the stored value verbatim would produce a genuine ciphertext archive on one
mode and a plaintext credential dump on the other, from the same "safe by default" call.
Normalising here is what makes the archive's security property independent of the mode it
came from, and a ciphertext export with no key configured is **refused** rather than
quietly downgraded.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from device_mcp_gateway.backup.envelope import (
    Argon2Params,
    BackupError,
    KIND_CIPHERTEXT,
    KIND_PORTABLE,
    build_envelope,
    check_passphrase,
    fernet_for_passphrase,
    seal_canary,
)
from device_mcp_gateway.shared.crypto import CredentialCodec

# Registration inputs — the fields a restore feeds back through register_device. Runtime
# state is deliberately absent; see the module docstring.
_DEVICE_FIELDS = (
    "hostname",
    "base_url",
    "spec_url",
    "transport",
    "auth_type",
    "rate_limit_rps",
    "upstream_kind",
    "upstream_transport",
)


class CiphertextExportUnavailable(BackupError):
    """A ciphertext export was requested on a stack with no ``MCP_SECRET_KEY``.

    Refused rather than served: the archive would be labelled ciphertext and contain
    plaintext credentials, which is the one outcome the default kind exists to prevent.
    """


def credential_plaintext(blob: str | None, codec: CredentialCodec) -> str | None:
    """The plaintext JSON behind a stored ``auth_config``, whichever way it was stored.

    Tries a decrypt and falls back to treating the value as plaintext. Deliberately not
    ``codec.is_current`` — that answers "encrypted under the *primary* key", so during a
    key rotation a value under the older key would look like plaintext and be encrypted a
    second time, producing an archive of double-wrapped credentials that decrypt to
    ciphertext and fail nothing loudly.
    """
    if not blob:
        return None
    if not codec.enabled:
        return blob
    from cryptography.fernet import InvalidToken

    try:
        return codec.decrypt(blob)
    except InvalidToken:
        # Not encrypted under any configured key: embedded mode's plaintext JSON.
        return blob


async def build_archive(
    *,
    registry: Any,
    codec: CredentialCodec,
    config: dict,
    kind: str = KIND_CIPHERTEXT,
    passphrase: str | None = None,
    include_deadletters: bool = False,
    gateway_version: str,
    mode: str,
) -> dict[str, Any]:
    """Collect the registry into a sealed archive.

    Raises :class:`CiphertextExportUnavailable` when a ciphertext export has no key to
    encrypt with, and :class:`~device_mcp_gateway.backup.envelope.PassphraseTooWeak` when a
    portable export's passphrase is below the configured floor.
    """
    backup_cfg = config.get("backup", {})

    if kind == KIND_CIPHERTEXT:
        if not codec.enabled:
            raise CiphertextExportUnavailable(
                "a ciphertext archive needs MCP_SECRET_KEY to encrypt credentials with, and "
                "none is configured — this stack would emit them in plaintext. Set a Fernet "
                "key, or request a portable archive (kind=portable), which carries its own "
                "passphrase-derived encryption."
            )
        sealer: Any = codec
        kdf_envelope = None
    elif kind == KIND_PORTABLE:
        passphrase = check_passphrase(passphrase, minimum=int(backup_cfg.get("passphrase_min_length", 16)))
        params = Argon2Params.generate(
            memory_cost_kib=int(backup_cfg.get("argon2_memory_cost_kib", 65536)),
            iterations=int(backup_cfg.get("argon2_iterations", 3)),
            lanes=int(backup_cfg.get("argon2_lanes", 4)),
        )
        # Derived once for the whole archive, not per credential.
        sealer = fernet_for_passphrase(passphrase, params)
        kdf_envelope = params.to_envelope(
            passphrase_min_length=int(backup_cfg.get("passphrase_min_length", 16)),
        )
    else:
        raise BackupError(f"unknown archive kind {kind!r}")

    backend = registry._backend
    devices_raw = await registry.list_devices()

    devices: list[dict[str, Any]] = []
    tool_changes: dict[str, Any] = {}
    dead_letters: dict[str, list[dict]] = {}
    deadletter_limit = int(backup_cfg.get("deadletter_limit", 1000))

    for cfg_obj in devices_raw:
        record = {field: getattr(cfg_obj, field, None) for field in _DEVICE_FIELDS}
        # Governance counter travels with the device: resetting it on restore would tell
        # every polling client the tool set had rolled back (F-41).
        record["tools_revision"] = getattr(cfg_obj, "tools_revision", 0)
        plaintext = credential_plaintext(getattr(cfg_obj, "auth_config", None), codec)
        record["auth_config"] = _seal(plaintext, sealer) if plaintext else None
        devices.append(record)

        change = await backend.get_last_tool_change(cfg_obj.hostname)
        if change:
            tool_changes[cfg_obj.hostname] = change

        if include_deadletters:
            entries = await backend.dead_letter_export(cfg_obj.hostname, count=deadletter_limit)
            if entries:
                dead_letters[cfg_obj.hostname] = entries

    counts = {
        "devices": len(devices),
        "tool_changes": len(tool_changes),
        "dead_letters": sum(len(v) for v in dead_letters.values()),
    }
    archive = build_envelope(
        kind=kind,
        gateway_version=gateway_version,
        mode=mode,
        canary=seal_canary(sealer),
        counts=counts,
        kdf=kdf_envelope,
    )
    archive["devices"] = devices
    archive["tool_changes"] = tool_changes
    archive["dead_letters"] = dead_letters

    logger.info(
        f"Backup archive built: kind={kind} devices={counts['devices']} "
        f"tool_changes={counts['tool_changes']} dead_letters={counts['dead_letters']}"
    )
    return archive


def _seal(plaintext: str, sealer: Any) -> str:
    """Encrypt a credential blob under whatever seals this archive (codec or Fernet)."""
    out = sealer.encrypt(plaintext if isinstance(sealer, CredentialCodec) else plaintext.encode())
    return out if isinstance(out, str) else out.decode()
