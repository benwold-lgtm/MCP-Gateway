# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Restore a backup archive (ADR-0011).

Restoring is not the inverse of exporting, and the difference is the whole design.

**Nothing is written until the entire archive has been decrypt-tested.** The preflight
opens the canary and then every credential in the archive; any failure aborts everything.
A partial apply is the outcome worth the most trouble to avoid — it leaves a registry
half-migrated between two key generations, with no record of where the boundary fell. The
canary is what makes the check total: an archive of devices that all use ``auth_type:
none`` has no credential ciphertext, so without it a wrong-key restore would sail through
and fail at the far end.

The preflight differs by kind on purpose. A ciphertext archive is tested against this
stack's ``MCP_SECRET_KEY`` — a key mismatch is *the* expected failure and is named as such.
A portable archive is tested against the passphrase only, because it is key-independent by
design; demanding the target's key for one would defeat the reason it exists.

**Each device is replayed through the ordinary registration path**, gates and all
(``validate_device_registration``, F-67), never a raw Redis write. That is a security
property rather than tidiness: a ``backup:write`` holder must not be able to reinstate a
device the current egress policy forbids. It follows that a restore can legitimately fail
*on a device*, and those failures are reported per device rather than swallowed or
escalated into a failed batch.

``dry_run=True`` is the default. The destructive direction is never the one you get by
omission — and a dry run runs the same preflight and the same per-device gates, so its
report is a real prediction rather than a parse.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from loguru import logger

from device_mcp_gateway.backup.envelope import (
    Argon2Params,
    BackupError,
    KIND_CIPHERTEXT,
    KIND_PORTABLE,
    fernet_for_passphrase,
    parse_archive,
    verify_canary,
)
from device_mcp_gateway.registry.validation import validate_device_registration
from device_mcp_gateway.security.url_policy import resolve_allow_private, resolve_allowed_ports
from device_mcp_gateway.shared.crypto import CredentialCodec

ON_CONFLICT_SKIP = "skip"
ON_CONFLICT_OVERWRITE = "overwrite"
ON_CONFLICT_FAIL = "fail"
ON_CONFLICT_MODES = (ON_CONFLICT_SKIP, ON_CONFLICT_OVERWRITE, ON_CONFLICT_FAIL)

# Per-device outcomes, reported back to the caller.
OUTCOME_RESTORED = "restored"
OUTCOME_WOULD_RESTORE = "would_restore"
OUTCOME_SKIPPED = "skipped"
OUTCOME_FAILED = "failed"


class RestorePreflightError(BackupError):
    """The archive could not be opened. Raised before anything is written, always."""


def _opener(archive: dict[str, Any], codec: CredentialCodec, passphrase: str | None) -> Any:
    """The thing that decrypts this archive's credentials — codec or passphrase Fernet."""
    kind = archive.get("kind")
    if kind == KIND_PORTABLE:
        if not passphrase:
            raise RestorePreflightError("this is a portable archive; it needs the passphrase it was exported with")
        kdf = archive.get("kdf")
        if not isinstance(kdf, dict):
            raise RestorePreflightError("portable archive is missing its key-derivation parameters")
        # Derived from what the ARCHIVE declares, never from today's config: an archive
        # made under a different cost would otherwise derive a different key and look
        # exactly like a wrong passphrase.
        return fernet_for_passphrase(passphrase, Argon2Params.from_envelope(kdf))
    if kind == KIND_CIPHERTEXT:
        if not codec.enabled:
            raise RestorePreflightError(
                "this is a ciphertext archive and this stack has no MCP_SECRET_KEY to open it "
                "with. Restore it into a stack sharing that key, or use a portable archive."
            )
        return codec
    raise RestorePreflightError(f"unknown archive kind {kind!r}")


def _open_credential(blob: str, opener: Any) -> str:
    plaintext = opener.decrypt(blob if isinstance(opener, CredentialCodec) else blob.encode())
    return plaintext if isinstance(plaintext, str) else plaintext.decode()


def preflight(archive: dict[str, Any], codec: CredentialCodec, passphrase: str | None) -> Any:
    """Decrypt-test the whole archive. Returns the opener, or raises.

    Every credential, not a sample: the point is that a restore never discovers halfway
    through that it cannot read the rest.
    """
    opener = _opener(archive, codec, passphrase)
    try:
        verify_canary(archive, opener)
    except BackupError as exc:
        raise RestorePreflightError(str(exc)) from exc

    for record in archive.get("devices", []):
        blob = record.get("auth_config")
        if not blob:
            continue
        try:
            _open_credential(blob, opener)
        except Exception as exc:
            raise RestorePreflightError(
                f"credential for device '{record.get('hostname')}' could not be decrypted "
                f"({type(exc).__name__}). Nothing has been written — the whole restore is "
                "aborted rather than applied in part."
            ) from exc
    return opener


async def restore_archive(
    *,
    raw_archive: Any,
    registry: Any,
    codec: CredentialCodec,
    config: dict,
    passphrase: str | None = None,
    dry_run: bool = True,
    on_conflict: str = ON_CONFLICT_SKIP,
    include_deadletters: bool = False,
) -> dict[str, Any]:
    """Replay an archive into this stack. Returns a per-device report."""
    if on_conflict not in ON_CONFLICT_MODES:
        raise BackupError(f"on_conflict must be one of: {', '.join(ON_CONFLICT_MODES)}")

    archive = parse_archive(raw_archive)
    opener = preflight(archive, codec, passphrase)  # raises before any write

    allow_private = resolve_allow_private(config)
    allowed_ports = resolve_allowed_ports(config)
    backend = registry._backend

    results: list[dict[str, Any]] = []
    for record in archive.get("devices", []):
        results.append(
            await _restore_one(
                record,
                registry=registry,
                backend=backend,
                archive=archive,
                opener=opener,
                dry_run=dry_run,
                on_conflict=on_conflict,
                allow_private=allow_private,
                allowed_ports=allowed_ports,
                include_deadletters=include_deadletters,
            )
        )

    counts: dict[str, int] = {}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

    logger.info(f"Restore {'(dry run) ' if dry_run else ''}complete: {counts}")
    return {
        "dry_run": dry_run,
        "kind": archive.get("kind"),
        "on_conflict": on_conflict,
        "created_at": archive.get("created_at"),
        "counts": counts,
        "devices": results,
    }


async def _restore_one(
    record: dict[str, Any],
    *,
    registry: Any,
    backend: Any,
    archive: dict[str, Any],
    opener: Any,
    dry_run: bool,
    on_conflict: str,
    allow_private: bool,
    allowed_ports: set[int] | None,
    include_deadletters: bool,
) -> dict[str, Any]:
    hostname = record.get("hostname") or "<unnamed>"

    def _result(outcome: str, reason: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"hostname": hostname, "outcome": outcome}
        if reason:
            out["reason"] = reason
        return out

    upstream_kind = record.get("upstream_kind") or "openapi"
    upstream_transport = record.get("upstream_transport") or "http"
    spec_url = record.get("spec_url")
    try:
        # The same gates POST /v1/devices runs (F-67). `declared` names only the upstream
        # keys an OpenAPI device may legitimately carry, so a restored record does not trip
        # the "upstream_transport on an OpenAPI device" rule on a value it merely stored.
        validate_device_registration(
            hostname=hostname,
            base_url=record.get("base_url") or "",
            spec_url=spec_url,
            transport=record.get("transport") or "sse",
            upstream_kind=upstream_kind,
            upstream_transport=upstream_transport,
            declared={"upstream_kind"} if upstream_kind == "mcp" else set(),
            allow_private=allow_private,
            allowed_ports=allowed_ports,
        )
    except HTTPException as exc:
        # A device the current policy no longer permits. Correct behaviour, reported —
        # the restore does not become a way to reinstate what registration would refuse.
        return _result(OUTCOME_FAILED, str(exc.detail))

    existing = await registry.get_device(hostname)
    if existing is not None:
        if on_conflict == ON_CONFLICT_SKIP:
            return _result(OUTCOME_SKIPPED, "already registered")
        if on_conflict == ON_CONFLICT_FAIL:
            return _result(OUTCOME_FAILED, "already registered (on_conflict=fail)")

    if dry_run:
        return _result(OUTCOME_WOULD_RESTORE)

    try:
        auth = _auth_for(record, opener)
    except Exception as exc:  # noqa: BLE001 — reported per device, never fatal to the batch
        return _result(OUTCOME_FAILED, f"credential could not be rebuilt: {exc}")

    kwargs = dict(
        hostname=hostname,
        base_url=record.get("base_url"),
        spec_url=spec_url,
        auth=auth,
        transport=record.get("transport") or "sse",
        rate_limit_rps=record.get("rate_limit_rps"),
        upstream_kind=upstream_kind,
        upstream_transport=upstream_transport,
    )
    try:
        if existing is not None:  # on_conflict == overwrite
            await registry.replace_device(**kwargs)
        else:
            await registry.register_device(**kwargs)
    except HTTPException as exc:
        return _result(OUTCOME_FAILED, str(exc.detail))
    except Exception as exc:  # noqa: BLE001
        return _result(OUTCOME_FAILED, f"{type(exc).__name__}: {exc}")

    await _restore_governance(hostname, record, archive, backend, include_deadletters=include_deadletters)
    return _result(OUTCOME_RESTORED)


def _auth_for(record: dict[str, Any], opener: Any) -> Any:
    """Rebuild the device's auth handler from the archived credential.

    Uses the existing ``_auth_from_config``, which is already the exact inverse of the
    ``_auth_to_record`` that wrote it — reimplementing the mapping here is how the two
    drift.
    """
    from device_mcp_gateway.worker.runner import _auth_from_config

    blob = record.get("auth_config")
    if not blob:
        return None
    return _auth_from_config(record.get("auth_type"), _open_credential(blob, opener))


async def _restore_governance(
    hostname: str,
    record: dict[str, Any],
    archive: dict[str, Any],
    backend: Any,
    *,
    include_deadletters: bool,
) -> None:
    """Put back what registration does not reconstruct.

    ``register_device`` starts a device at ``tools_revision=0`` with no change history,
    which is right for a new device and wrong for a restored one: a client polling the
    revision would read the reset as the tool set having rolled back (F-41). These are
    written after the replay rather than through it, because they are governance metadata
    *about* a registration rather than inputs *to* one — the egress policy has nothing to
    say about them.
    """
    change = (archive.get("tool_changes") or {}).get(hostname)
    revision = record.get("tools_revision") or 0
    fields: dict[str, Any] = {}
    if revision:
        fields["tools_revision"] = revision
    if fields:
        await backend.update_device_fields(hostname, **fields)
    if change:
        await backend.set_last_tool_change(hostname, change)

    if include_deadletters:
        entries = (archive.get("dead_letters") or {}).get(hostname) or []
        if entries:
            written = await backend.dead_letter_import(hostname, entries)
            logger.info(f"Restored {written} dead-letter entr{'y' if written == 1 else 'ies'} for {hostname}")
