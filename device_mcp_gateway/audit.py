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

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from loguru import logger

AUDIT_OUTCOME_SUCCESS = "success"
AUDIT_OUTCOME_DENIED = "denied"
AUDIT_OUTCOME_ERROR = "error"


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
    """Emit one structured audit record (``event="audit"``) with the canonical schema."""
    logger.bind(
        event="audit",
        action=action,
        subject=subject,
        rid=rid,
        target=target,
        outcome=outcome,
        **extra,
    ).info(f"audit:{action} {outcome}")


def subject_of(request: Any) -> str:
    """Resolve the audit subject from a request's stashed Principal (or 'unauthenticated')."""
    principal = getattr(getattr(request, "state", None), "principal", None)
    return principal.subject if principal is not None else "unauthenticated"


def audit_request(request: Any, action: str, *, outcome: str, target: str | None = None, **extra: Any) -> None:
    """Emit an audit record for an HTTP request, pulling subject + rid off ``request``."""
    rid = getattr(getattr(request, "state", None), "request_id", "-")
    audit_event(action, subject=subject_of(request), outcome=outcome, rid=rid, target=target, **extra)


__all__ = [
    "AUDIT_OUTCOME_SUCCESS",
    "AUDIT_OUTCOME_DENIED",
    "AUDIT_OUTCOME_ERROR",
    "redact_url",
    "audit_event",
    "audit_request",
    "subject_of",
]
