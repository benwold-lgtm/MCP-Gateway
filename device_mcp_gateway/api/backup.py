# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Backup export and restore routes (ADR-0011, restore split per ADR-0018 §6).

Export is two routes for one operation, and the split is about where a secret is allowed
to appear:

- ``GET /v1/admin/backup`` — the ciphertext default. Needs no secret in the request at all,
  so a plain GET is safe and stays the easy, scriptable path a scheduled job uses.
- ``POST /v1/admin/backup`` — either kind, with the passphrase in a **JSON body**. A
  portable export must come through here. A passphrase in a query string would be written
  to every proxy and access log between the caller and the gateway, kept in shell history,
  and forwarded in a ``Referer`` — and this one passphrase unlocks every credential in the
  stack.

``backup:export-portable`` is checked inside the handler rather than as a router
``Depends``, because whether it is required depends on the request body.

Restore is also two routes, and the split is about scope: ``POST /v1/admin/restore/preview``
writes nothing and needs only ``backup:read``; ``POST /v1/admin/restore/apply`` is
destructive and needs ``backup:write``. See the comment above the routes themselves.
"""

from __future__ import annotations

import secrets

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from device_mcp_gateway import __version__
from device_mcp_gateway.audit import AUDIT_OUTCOME_DENIED, AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.backup.envelope import ARCHIVE_KINDS, BackupError, KIND_CIPHERTEXT, KIND_PORTABLE
from device_mcp_gateway.backup.export import build_archive
from device_mcp_gateway.backup.restore import ON_CONFLICT_SKIP, restore_archive
from device_mcp_gateway.cfg import plan_digest_validity_seconds, resolve_mode
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.rbac import (
    Principal,
    SCOPE_BACKUP_EXPORT_PORTABLE,
    SCOPE_BACKUP_READ,
    SCOPE_BACKUP_WRITE,
    require_scope,
)
from device_mcp_gateway.shared.canonical_json import compute_digest
from device_mcp_gateway.shared.crypto import secret_keys_from_config
from device_mcp_gateway.shared.plan_token import (
    InvalidPlanToken,
    PlanTokenExpired,
    derive_plan_token_keys,
    mint_plan_token,
    verify_plan_token,
)

router = APIRouter()

# An export reads the whole registry and, for a portable archive, runs Argon2id at 64 MiB.
# Both budgets must be satisfied (F-16): the per-identity limit is the one that matters
# here, since a credential dump is worth repeating from a single authenticated key.
_EXPORT_LIMITS = [
    Depends(rate_limit("10/minute", "backup_export")),
    Depends(rate_limit_principal("20/minute", "backup_export")),
]


#: Where a *minted* passphrase is delivered. Single use in the sense that matters: it is
#: generated per export, returned once, and stored nowhere on this side.
PASSPHRASE_HEADER = "X-Backup-Passphrase"


async def _export(
    request: Request,
    *,
    kind: str,
    passphrase: str | None,
    include_deadletters: bool,
) -> JSONResponse:
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
        result = await build_archive(
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

    archive = result.archive

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
        # *That* one was minted is recorded; the passphrase itself never is. A responder
        # reconstructing who could open which archive needs the first and must not have the
        # second.
        **({"passphrase_source": "generated"} if result.passphrase else {}),
    )

    # The archive is the whole body — unchanged contract — and a minted passphrase rides in a
    # header instead.
    #
    # This is the important shape decision in ADR-0011. Wrapping the response as
    # `{archive, passphrase}` reads more naturally and is a trap: any caller that saves the
    # body to a file then writes the passphrase *inside the archive it protects*, silently,
    # and produces something `restore` will not accept either. A header keeps the body a
    # valid archive for every existing client and puts the secret somewhere a file-writing
    # caller cannot accidentally persist.
    #
    # It must never be logged. The gateway does not log response headers; anything that
    # proxies this — the BFF included — inherits that obligation.
    response = JSONResponse(content=archive)
    if result.passphrase:
        response.headers[PASSPHRASE_HEADER] = result.passphrase
    return response


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


# Restore is split into two structurally separate routes (ADR-0018 §6). A preview is
# read-level work — it parses a caller-supplied archive and simulates it against the live
# registry, writing nothing and disclosing only registry-existence information that
# `backup:read` already covers. Only the apply is destructive. Splitting by *scope* means
# the whole iterative loop (preview, read the report, adjust on_conflict, preview again)
# runs with no elevation held at all, and `backup:write` is acquired once, for the single
# call that overwrites the registry.
#
# The split is a route-level dependency, not a check inside a shared handler that reads
# a `dry_run` field after the fact: the destructive direction must never be reachable on
# read-level authority through a body a caller controls. The apply route below has no
# `dry_run` parameter to get wrong.
#
# The pair is bound by a plan_token: the preview computes plan_digest over its own parsed,
# canonicalized inputs and returns an HMAC-signed token committing to it; the apply must
# submit that token, and the gateway recomputes the digest of ITS OWN inputs and refuses
# (ERR_PLAN_STALE) unless the token verifies and its digest matches. This is what makes
# restore repeatable rather than single-use: unlimited preview/adjust/preview, and every
# apply bound to a plan a human actually read, without rationing how many attempts an
# operator gets (ADR-0018 §6, "What replaces it is a better control").

_RESTORE_PREVIEW_LIMITS = [
    Depends(rate_limit("10/minute", "backup_restore_preview")),
    Depends(rate_limit_principal("20/minute", "backup_restore_preview")),
]
_RESTORE_APPLY_LIMITS = [
    Depends(rate_limit("10/minute", "backup_restore_apply")),
    Depends(rate_limit_principal("20/minute", "backup_restore_apply")),
]

#: Process-local fallback HMAC key, used only when no MCP_SECRET_KEY is configured at all
#: (embedded/dev mode — CredentialCodec.from_config's own docstring calls this "convenient
#: for local/embedded development"). A plan_token minted under it does not survive a
#: restart, which only means "preview again" in that mode — the same cost a keyless
#: deployment already accepts for credential storage, never a security regression, since no
#: key existed to bind to either way.
#:
#: **This used to claim distributed mode could not reach it, because that mode "refuses to
#: start without a key". It does not.** `main.py`'s refusal is gated on
#: `and not allow_plaintext_credentials` — an override its own error message advertises. A
#: distributed stack under that override reached this fallback, and the key is *per process*,
#: so on more than one replica the preview minted a token the apply's replica could not
#: verify: `ERR_PLAN_STALE`, saying "preview again and submit the plan_token from that
#: preview", advice that fails identically forever. A restore that cannot be completed by any
#: correct operator behaviour, and nothing named the reason.
_EPHEMERAL_PLAN_TOKEN_KEY = secrets.token_bytes(32)


def _plan_token_keys(config: dict) -> list[bytes]:
    """The HMAC keys a plan_token is minted and verified under.

    Refuses rather than falling back when the fallback cannot work. In distributed mode the
    process-local key is not merely weaker, it is *wrong*: whichever replica serves the apply
    is not the one that minted the token. Failing here — at preview, before an operator has
    an archive pasted and a plan on screen — names the cause at the point of the mistake,
    which an `ERR_PLAN_STALE` at apply can never do (see `_plan_stale`: it is a legitimate,
    expected verdict, so it cannot also carry "your stack is misconfigured").
    """
    secret_keys = secret_keys_from_config(config)
    if secret_keys:
        return derive_plan_token_keys(secret_keys)
    if resolve_mode(config) == "distributed":
        raise HTTPException(
            status_code=503,
            detail=(
                "This stack cannot mint a restore plan token: no MCP_SECRET_KEY is configured, "
                "so the token would be signed with a per-process key and any other replica "
                "would reject the apply as stale. Set MCP_SECRET_KEY (the same value on every "
                "replica) and retry. Restore is the one operation gateway.allow_plaintext_"
                "credentials cannot paper over."
            ),
        )
    return [_EPHEMERAL_PLAN_TOKEN_KEY]


#: The fields the plan digest commits to — the entire canonicalized apply request, by
#: construction (ADR-0018 §6). `plan_token` itself is deliberately excluded: it cannot be
#: part of what it authenticates, or a token would need to predict its own value.
_PLAN_DIGEST_FIELDS = ("archive", "passphrase", "on_conflict", "include_deadletters")


async def _parse_restore_body(request: Request) -> tuple[object, str | None, str, bool, str | None]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be a JSON object containing an 'archive'")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    archive = data.get("archive")
    if archive is None:
        raise HTTPException(status_code=400, detail="body must contain 'archive' (the exported document)")

    on_conflict = data.get("on_conflict") or ON_CONFLICT_SKIP
    return (
        archive,
        data.get("passphrase"),
        on_conflict,
        bool(data.get("include_deadletters", False)),
        data.get("plan_token"),
    )


def _plan_stale(detail: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "error_code": "ERR_PLAN_STALE",
            "message": detail,
            # Named because the digest binds the whole request, by construction — the
            # gateway persists no plan to diff against, so this is the field space a
            # divergence could be in, never a computed diff, and never a previous value
            # (ADR-0018 §6: "A stale rejection names which fields diverged. It never
            # returns the previewed value, nor the previewed digest's inputs.").
            "fields": list(_PLAN_DIGEST_FIELDS),
        },
    )


async def _run_restore(request: Request, *, dry_run: bool) -> dict:
    archive, passphrase, on_conflict, include_deadletters, plan_token = await _parse_restore_body(request)
    digest = compute_digest(
        {
            "archive": archive,
            "passphrase": passphrase,
            "on_conflict": on_conflict,
            "include_deadletters": include_deadletters,
        }
    )

    if not dry_run:
        # The apply must reference the plan it was previewed from. Checked before anything
        # is executed — no restore_archive call happens on a stale or forged apply.
        if not plan_token:
            raise HTTPException(
                status_code=400, detail="apply requires 'plan_token', from a preceding preview's response"
            )

        stale_cause: str | None = None
        keys = _plan_token_keys(request.app.state.config)
        max_age = plan_digest_validity_seconds(request.app.state.config)
        try:
            verified = verify_plan_token(plan_token, keys=keys, max_age_seconds=max_age)
        except PlanTokenExpired:
            # The mechanism working as intended: legitimate drift, just past the window.
            stale_cause = "expired"
        except InvalidPlanToken:
            # Malformed, or signed by no key this stack holds — replayed, copied, or
            # guessed against a request it never described (ADR-0018 §6's other cause).
            stale_cause = "invalid_signature"
        else:
            if verified.digest != digest:
                # Verifies and is fresh, but commits to a different request: the
                # legitimate-drift case — something changed since the preview.
                stale_cause = "digest_mismatch"

        if stale_cause is not None:
            audit_request(
                request,
                "backup.restore",
                outcome=AUDIT_OUTCOME_DENIED,
                target="registry",
                dry_run=dry_run,
                plan_digest=digest,
                reason="ERR_PLAN_STALE",
                plan_stale_cause=stale_cause,
            )
            raise _plan_stale(
                "plan_token does not match this request (it may be stale, reused from a "
                "different preview, or expired). Preview again and submit the plan_token "
                "that preview returns."
            )

    try:
        report = await restore_archive(
            raw_archive=archive,
            registry=request.app.state.registry,
            codec=request.app.state.codec,
            config=request.app.state.config,
            passphrase=passphrase,
            dry_run=dry_run,
            on_conflict=on_conflict,
            include_deadletters=include_deadletters,
        )
    except BackupError as exc:
        # Includes every preflight failure — wrong key, wrong passphrase, missing canary.
        # Audited: a failed restore attempt is as interesting to a responder as one that
        # worked, and a preview is the natural reconnaissance step before an apply.
        audit_request(
            request,
            "backup.restore",
            outcome=AUDIT_OUTCOME_DENIED,
            target="registry",
            dry_run=dry_run,
            plan_digest=digest,
            reason=type(exc).__name__,
        )
        raise HTTPException(status_code=409, detail=str(exc))

    audit_request(
        request,
        "backup.restore",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target="registry",
        dry_run=dry_run,
        plan_digest=digest,
        kind=report["kind"],
        on_conflict=on_conflict,
        # A restore that discarded an archived pin, or that left a device to
        # trust-on-first-use, is a change in what this stack trusts — the audit chain is
        # where ADR-0015 §6 puts those, and a responder reading only the audit record
        # should not have to infer it from the device counts.
        fingerprint_warnings=report.get("fingerprint_warnings", 0),
        **{f"count_{k}": v for k, v in report["counts"].items()},
    )

    report["plan_digest"] = digest
    if dry_run:
        report["plan_token"] = mint_plan_token(digest, keys=_plan_token_keys(request.app.state.config))
    return report


@router.post(
    "/admin/restore/preview",
    dependencies=[Depends(require_scope(SCOPE_BACKUP_READ))] + _RESTORE_PREVIEW_LIMITS,
)
async def restore_preview(request: Request):
    """Simulate replaying an archive into this stack. Writes nothing.

    Body: ``{archive, passphrase?, on_conflict?, include_deadletters?}``. Runs the same
    fail-closed preflight and the same per-device gates as an apply, so its report
    predicts rather than guesses. The response carries ``plan_digest`` and ``plan_token``
    — submit ``plan_token`` back to ``/admin/restore/apply`` to apply exactly this plan.
    """
    return await _run_restore(request, dry_run=True)


@router.post(
    "/admin/restore/apply",
    dependencies=[Depends(require_scope(SCOPE_BACKUP_WRITE))] + _RESTORE_APPLY_LIMITS,
)
async def restore_apply(request: Request):
    """Replay an archive into this stack. Destructive: overwrites the registry.

    Body: ``{archive, passphrase?, on_conflict?, include_deadletters?, plan_token}``.
    ``plan_token`` must come from a preceding preview of this exact request — a mismatch,
    forged, or expired token is refused as ``ERR_PLAN_STALE`` before anything is written.
    """
    return await _run_restore(request, dry_run=False)
