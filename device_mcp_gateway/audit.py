# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Audit trail + log redaction (Tier-1 F-55 / F-56 / F-59).

A single seam for *who did what, to what, with what outcome*, so privileged actions
and access denials are answerable from the logs — a core SOC 2 (CC) / HIPAA
(§164.312(b)) expectation. Previously only tool dispatch was audited; device CRUD
and 401/403 carried no actor.

Audit records are emitted with ``event="audit"`` and a stable field schema so a log
pipeline can filter and forward them:

    action   - dotted verb, e.g. "device.create", "auth.authenticate", "authz.check"
    subject  - the principal (e.g. "key:admin", or "unauthenticated")
    rid      - the request id, matching the access log and X-Request-Id
    target   - what was acted on (hostname, or "METHOD /path")
    outcome  - "success" | "denied" | "error"
    + any extra context (reason, scope, …)

``redact_url`` strips credentials from URLs before they are logged — a device
``base_url`` may embed ``user:pass@host`` (F-59), which must never reach the logs.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from loguru import logger

AUDIT_OUTCOME_SUCCESS = "success"
AUDIT_OUTCOME_DENIED = "denied"
AUDIT_OUTCOME_ERROR = "error"

# Genesis link for the tamper-evident audit hash-chain (F-57).
_GENESIS = "0" * 64
# Fields bound onto an audit record that are chain metadata / framing, not part of
# the hashed payload. Everything else under the record's ``extra`` is the payload.
_CHAIN_META = frozenset({"event", "audit_seq", "audit_prev", "audit_hash"})


def _record_hash(seq: int, prev: str, payload: dict[str, Any]) -> str:
    """Hash one audit record: sha256 over seq, the previous record's hash, and a
    canonical (sort-keyed) serialisation of the payload. Recomputed identically by
    the verifier, so any edit/reorder/deletion breaks the chain (F-57)."""
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{seq}\n{prev}\n{canon}".encode()).hexdigest()


class _AuditChain:
    """In-process, append-only hash chain over audit records (F-57).

    Each record links to the previous via its hash, so deleting, editing, or
    reordering any record is detectable by replaying the chain. The chain is seeded
    from the tail of the existing audit log on startup so it continues across
    process restarts; combined with forwarding the audit stream to an append-only
    sink (SIEM/WORM), this gives end-to-end tamper-evidence.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = _GENESIS

    def advance(self, payload: dict[str, Any]) -> tuple[int, str, str]:
        """Return ``(seq, prev, hash)`` for the next record and roll the chain head."""
        with self._lock:
            seq, prev = self._seq, self._prev
            h = _record_hash(seq, prev, payload)
            self._seq, self._prev = seq + 1, h
            return seq, prev, h

    def seed(self, *, next_seq: int, prev: str) -> None:
        with self._lock:
            self._seq, self._prev = next_seq, prev

    def reset(self) -> None:
        self.seed(next_seq=0, prev=_GENESIS)


_chain = _AuditChain()


def reset_audit_chain() -> None:
    """Reset the audit chain to genesis (tests + a fresh-start anchor)."""
    _chain.reset()


def init_audit_chain(audit_file: str) -> None:
    """Continue the hash chain from the last record already in ``audit_file`` so a
    restart doesn't reset the chain (which would otherwise look like tampering)."""
    last = _read_last_audit_extra(audit_file)
    if last and isinstance(last.get("audit_seq"), int) and isinstance(last.get("audit_hash"), str):
        _chain.seed(next_seq=last["audit_seq"] + 1, prev=last["audit_hash"])


def _read_last_audit_extra(audit_file: str) -> dict[str, Any] | None:
    """Return the ``extra`` dict of the last audit record in a serialised log file,
    or None if the file is absent/empty/unreadable (→ chain starts at genesis)."""
    try:
        with open(audit_file, encoding="utf-8") as fh:
            last = None
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    extra = json.loads(line).get("record", {}).get("extra", {})
                except (ValueError, AttributeError):
                    continue
                if extra.get("event") == "audit":
                    last = extra
            return last
    except OSError:
        return None


def redact_url(url: str | None) -> str:
    """Return ``url`` with any ``user:pass@`` userinfo replaced by ``***@`` (F-59).

    Credentials embedded in a device URL must never be logged. Clean URLs are returned
    unchanged; an unparseable value collapses to a safe placeholder.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    if not (parts.username or parts.password):
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, f"***@{host}", parts.path, parts.query, parts.fragment))


def audit_event(
    action: str,
    *,
    subject: str,
    outcome: str,
    rid: str = "-",
    target: str | None = None,
    **extra: Any,
) -> None:
    """Emit one structured audit record (``event="audit"``) with the canonical schema.

    Each record carries hash-chain fields (``audit_seq``/``audit_prev``/``audit_hash``)
    so the audit stream is tamper-evident (F-57): ``verify_audit_chain`` replays the
    chain and flags any altered, deleted, or reordered record.
    """
    audit_log(
        f"audit:{action} {outcome}",
        action=action,
        subject=subject,
        rid=rid,
        target=target,
        outcome=outcome,
        **extra,
    )


def audit_log(message: str, *, level: str = "INFO", **fields: Any) -> None:
    """Low-level chained audit emitter (the form behind ``audit_event``).

    Stamps the record with the tamper-evident hash-chain fields and tags it
    ``event="audit"`` so it lands on the dedicated audit sink (F-57). Use this for
    audit records that don't fit the action/subject/outcome shape — e.g. the
    per-call ``tool dispatch`` records — so *every* audit record is chained and the
    verifier never trips over an unchained one.
    """
    seq, prev, h = _chain.advance(fields)
    logger.bind(event="audit", audit_seq=seq, audit_prev=prev, audit_hash=h, **fields).log(level, message)


def subject_of(request: Any) -> str:
    """Resolve the audit subject from a request's stashed Principal (or 'unauthenticated')."""
    principal = getattr(getattr(request, "state", None), "principal", None)
    return principal.subject if principal is not None else "unauthenticated"


def audit_request(request: Any, action: str, *, outcome: str, target: str | None = None, **extra: Any) -> None:
    """Emit an audit record for an HTTP request, pulling subject + rid off ``request``."""
    rid = getattr(getattr(request, "state", None), "request_id", "-")
    audit_event(action, subject=subject_of(request), outcome=outcome, rid=rid, target=target, **extra)


def verify_audit_chain(
    audit_file: str, *, start_prev: str | None = None, start_seq: int | None = None
) -> tuple[bool, str]:
    """Replay a serialised audit log and verify its hash chain (F-57).

    Returns ``(ok, detail)``. Detects: an altered record (recomputed hash differs),
    a deleted/reordered record (a record's ``audit_prev`` no longer matches the
    previous record's hash), and a sequence gap. A file that starts mid-chain (after
    rotation) still verifies internally; pass ``start_prev``/``start_seq`` (the prior
    file's last hash/seq + 1) to chain across a rotation boundary.
    """
    prev = start_prev
    expected_seq = start_seq
    count = 0
    try:
        fh = open(audit_file, encoding="utf-8")
    except OSError as exc:
        return False, f"cannot read audit file: {exc}"
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                extra = json.loads(line).get("record", {}).get("extra", {})
            except (ValueError, AttributeError):
                continue
            if extra.get("event") != "audit":
                continue
            seq = extra.get("audit_seq")
            rec_prev = extra.get("audit_prev")
            rec_hash = extra.get("audit_hash")
            if not isinstance(seq, int) or not isinstance(rec_prev, str) or not isinstance(rec_hash, str):
                return False, f"record {count} missing chain fields (not produced by this gateway?)"
            payload = {k: v for k, v in extra.items() if k not in _CHAIN_META}
            if _record_hash(seq, rec_prev, payload) != rec_hash:
                return False, f"hash mismatch at seq {seq}: record was altered"
            if prev is not None and rec_prev != prev:
                return False, f"chain break before seq {seq}: a record was deleted or reordered"
            if expected_seq is not None and seq != expected_seq:
                return False, f"sequence gap: expected seq {expected_seq}, found {seq}"
            prev, expected_seq, count = rec_hash, seq + 1, count + 1
    return True, f"verified {count} audit record(s)"


__all__ = [
    "AUDIT_OUTCOME_SUCCESS",
    "AUDIT_OUTCOME_DENIED",
    "AUDIT_OUTCOME_ERROR",
    "redact_url",
    "audit_event",
    "audit_log",
    "audit_request",
    "subject_of",
    "verify_audit_chain",
    "init_audit_chain",
    "reset_audit_chain",
]
