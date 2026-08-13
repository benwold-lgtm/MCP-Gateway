# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Backup export routes (ADR-0011).

Two routes for one operation, and the split is about where a secret is allowed to appear:

- ``GET /v1/admin/backup`` — the ciphertext default. Needs no secret in the request at all,
  so a plain GET is safe and stays the easy, scriptable path a scheduled job uses.
- ``POST /v1/admin/backup`` — either kind, with the passphrase in a **JSON body**. A
  portable export must come through here. A passphrase in a query string would be written
  to every proxy and access log between the caller and the gateway, kept in shell history,
  and forwarded in a ``Referer`` — and this one passphrase unlocks every credential in the
  stack.

``backup:export-portable`` is checked inside the handler rather than as a router
``Depends``, because whether it is required depends on the request body.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from device_mcp_gateway import __version__
from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.backup.envelope import ARCHIVE_KINDS, BackupError, KIND_CIPHERTEXT, KIND_PORTABLE
from device_mcp_gateway.backup.export import build_archive
from device_mcp_gateway.backup.restore import ON_CONFLICT_SKIP, restore_archive
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.rbac import (
    Principal,
    SCOPE_BACKUP_EXPORT_PORTABLE,
    SCOPE_BACKUP_READ,
    SCOPE_BACKUP_WRITE,
    require_scope,
)

router = APIRouter()

# An export reads the whole registry and, for a portable archive, runs Argon2id at 64 MiB.
# Both budgets must be satisfied (F-16): the per-identity limit is the one that matters
# here, since a credential dump is worth repeating from a single authenticated key.
_EXPORT_LIMITS = [
    Depends(rate_limit("10/minute", "backup_export")),
    Depends(rate_limit_principal("20/minute", "backup_export")),
]


async def _export(
    request: Request,
    *,
    kind: str,
    passphrase: str | None,
    include_deadletters: bool,
) -> dict:
    """Shared body of both routes: authorize the kind, build, audit."""
    if kind not in ARCHIVE_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of: {', '.join(ARCHIVE_KINDS)}")

    principal: Principal | None = getattr(request.state, "principal", None)
    if kind == KIND_PORTABLE and (principal is None or not principal.has(SCOPE_BACKUP_EXPORT_PORTABLE)):
        # Audited as a denial in its own right: an attempt to take a key-independent dump
        # of every credential in the stack is exactly what a responder wants to see.
        audit_request(
            request,
            "backup.export_portable",
            outcome=AUDIT_OUTCOME_DENIED,
            target="registry",
            reason=f"missing_scope:{SCOPE_BACKUP_EXPORT_PORTABLE}",
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"Missing required scope: {SCOPE_BACKUP_EXPORT_PORTABLE}. A portable archive "
                "carries every device credential under one passphrase, so it is scoped "
                "separately from ordinary backups."
            ),
        )

    reg = request.app.state.registry
    try:
        archive = await build_archive(
            registry=reg,
            codec=request.app.state.codec,
            config=request.app.state.config,
            kind=kind,
            passphrase=passphrase,
            include_deadletters=include_deadletters,
            gateway_version=__version__,
            mode=request.app.state.mode,
        )
    except BackupError as exc:
        # 409, not 500: the request is well-formed and the operator can act on it (set a
        # key, lengthen the passphrase). The message says which.
        audit_request(
            request,
            _action_for(kind),
            outcome=AUDIT_OUTCOME_DENIED,
            target="registry",
            reason=type(exc).__name__,
        )
        raise HTTPException(status_code=409, detail=str(exc))

    # Audit every successful export, both kinds. A ciphertext export is a complete dump of
    # every credential in the stack; if previewing a restore is worth a record, this is.
    # The passphrase is never a field here.
    audit_request(
        request,
        _action_for(kind),
        outcome=AUDIT_OUTCOME_SUCCESS,
        target="registry",
        kind=kind,
        include_deadletters=include_deadletters,
        **{f"count_{k}": v for k, v in archive["counts"].items()},
    )
    return archive


def _action_for(kind: str) -> str:
    return "backup.export_portable" if kind == KIND_PORTABLE else "backup.export"


@router.get("/admin/backup", dependencies=[Depends(require_scope(SCOPE_BACKUP_READ))] + _EXPORT_LIMITS)
async def export_backup(
    request: Request,
    include_deadletters: bool = Query(False),
):
    """Ciphertext archive — credentials stay encrypted under this stack's MCP_SECRET_KEY.

    Restores into this stack or any stack sharing that key. For an archive that crosses key
    generations, POST to this path with ``kind=portable``.
    """
    return await _export(
        request,
        kind=KIND_CIPHERTEXT,
        passphrase=None,
        include_deadletters=include_deadletters,
    )


@router.post("/admin/backup", dependencies=[Depends(require_scope(SCOPE_BACKUP_READ))] + _EXPORT_LIMITS)
async def export_backup_with_body(request: Request):
    """Either archive kind. Body: ``{kind, passphrase, include_deadletters}``.

    The route that exists so a portable export's passphrase travels in a body rather than
    a URL.
    """
    try:
        data = await request.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    return await _export(
        request,
        kind=data.get("kind") or KIND_CIPHERTEXT,
        passphrase=data.get("passphrase"),
        include_deadletters=bool(data.get("include_deadletters", False)),
    )


@router.post(
    "/admin/restore",
    dependencies=[
        Depends(require_scope(SCOPE_BACKUP_WRITE)),
        Depends(rate_limit("10/minute", "backup_restore")),
        Depends(rate_limit_principal("20/minute", "backup_restore")),
    ],
)
async def restore_backup(request: Request):
    """Replay an archive into this stack.

    Body: ``{archive, passphrase?, dry_run?, on_conflict?, include_deadletters?}``.

    ``dry_run`` defaults to **true** — the destructive direction is never the one you get
    by omission. A dry run runs the same fail-closed preflight and the same per-device
    gates as a real one, so its report predicts rather than guesses.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be a JSON object containing an 'archive'")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    archive = data.get("archive")
    if archive is None:
        raise HTTPException(status_code=400, detail="body must contain 'archive' (the exported document)")

    dry_run = bool(data.get("dry_run", True))
    on_conflict = data.get("on_conflict") or ON_CONFLICT_SKIP

    try:
        report = await restore_archive(
            raw_archive=archive,
            registry=request.app.state.registry,
            codec=request.app.state.codec,
            config=request.app.state.config,
            passphrase=data.get("passphrase"),
            dry_run=dry_run,
            on_conflict=on_conflict,
            include_deadletters=bool(data.get("include_deadletters", False)),
        )
    except BackupError as exc:
        # Includes every preflight failure — wrong key, wrong passphrase, missing canary.
        # Audited: a failed restore attempt is as interesting to a responder as one that
        # worked, and a dry run is the natural reconnaissance step before a real one.
        audit_request(
            request,
            "backup.restore",
            outcome=AUDIT_OUTCOME_DENIED,
            target="registry",
            dry_run=dry_run,
            reason=type(exc).__name__,
        )
        raise HTTPException(status_code=409, detail=str(exc))

    audit_request(
        request,
        "backup.restore",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target="registry",
        dry_run=dry_run,
        kind=report["kind"],
        on_conflict=on_conflict,
        # A restore that discarded an archived pin, or that left a device to
        # trust-on-first-use, is a change in what this stack trusts — the audit chain is
        # where ADR-0015 §6 puts those, and a responder reading only the audit record
        # should not have to infer it from the device counts.
        fingerprint_warnings=report.get("fingerprint_warnings", 0),
        **{f"count_{k}": v for k, v in report["counts"].items()},
    )
    return report
