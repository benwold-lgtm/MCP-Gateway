# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""A durable, tenant-facing surface for signals that must not only be logged (ADR-0017 slice 5,
closing a gap confirmed while researching that ADR: ADR-0023 §2/§3's break-glass activation
today emits an audit event and a Prometheus alert, but nothing a tenant admin who isn't
watching Prometheus would ever see).

This is deliberately not an email/webhook/push channel — the gateway has no outbound
notification mechanism at all today, and building one is out of scope for this ADR. What this
gives instead is a durable, queryable list a tenant console can poll (`GET /v1/notifications`),
the same shape `PendingSupportRequestStore` already gives the tenant console's request inbox.
Two producers write to it: `breakglass.note_break_glass_use` on an activation, and
`api/support_requests.py`'s standing-consent self-issue path when a subject is self-issuing
often enough to flag (`support_grants`'s `SelfIssueActivityTracker`). Both are cases where no
per-instance human review happened, which is exactly when a passive, after-the-fact surface
matters most.

Capped by `LTRIM`, not TTL'd: a fixed-size recent list is the semantics wanted (the newest N
notifications, however old), not an expiring one that could go silently empty.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any, Protocol

from loguru import logger

from device_mcp_gateway.shared.keys import KEYS


@dataclass(frozen=True)
class TenantNotification:
    id: str
    kind: str
    subject: str
    message: str
    severity: str
    created_at: float
    #: True when this record was written to (or read from) the in-process fallback rather
    #: than the shared Redis list — the same degrade-and-flag posture every store in this
    #: codebase uses rather than losing the signal outright.
    degraded: bool = False


class TenantNotificationStore(Protocol):
    async def create(self, *, kind: str, subject: str, message: str, severity: str) -> TenantNotification: ...

    async def list_recent(self, *, limit: int = 50) -> list[TenantNotification]: ...


class InMemoryTenantNotificationStore:
    """Per-process store for embedded mode, tests, and the Redis-backed store's fallback."""

    def __init__(self, *, max_retained: int = 200) -> None:
        self._items: list[TenantNotification] = []
        self._max_retained = max_retained

    async def create(self, *, kind: str, subject: str, message: str, severity: str) -> TenantNotification:
        note = TenantNotification(
            id=str(uuid.uuid4()), kind=kind, subject=subject, message=message, severity=severity, created_at=time.time()
        )
        self._items.insert(0, note)
        del self._items[self._max_retained :]
        return note

    async def list_recent(self, *, limit: int = 50) -> list[TenantNotification]:
        return list(self._items[:limit])


class RedisTenantNotificationStore:
    """Store shared across gateway replicas. Falls back to an in-process store on any Redis
    error — same trade every other store in this codebase already makes."""

    def __init__(self, redis_client: Any, *, max_retained: int = 200) -> None:
        self._r = redis_client
        self._max_retained = max_retained
        self._fallback = InMemoryTenantNotificationStore(max_retained=max_retained)

    async def create(self, *, kind: str, subject: str, message: str, severity: str) -> TenantNotification:
        try:
            return await self._create(kind=kind, subject=subject, message=message, severity=severity)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"tenant notification store fell back to process-local state: {exc}")
            note = await self._fallback.create(kind=kind, subject=subject, message=message, severity=severity)
            return replace(note, degraded=True)

    async def _create(self, *, kind: str, subject: str, message: str, severity: str) -> TenantNotification:
        note = TenantNotification(
            id=str(uuid.uuid4()), kind=kind, subject=subject, message=message, severity=severity, created_at=time.time()
        )
        payload = json.dumps(
            {
                "id": note.id,
                "kind": note.kind,
                "subject": note.subject,
                "message": note.message,
                "severity": note.severity,
                "created_at": note.created_at,
            }
        )
        key = KEYS.tenant_notifications
        pipe = self._r.pipeline(transaction=True)
        pipe.lpush(key, payload)
        pipe.ltrim(key, 0, self._max_retained - 1)
        await pipe.execute()
        return note

    async def list_recent(self, *, limit: int = 50) -> list[TenantNotification]:
        try:
            return await self._list_recent(limit=limit)
        except Exception as exc:  # noqa: BLE001 — see class docstring
            logger.warning(f"tenant notification store fell back to process-local state: {exc}")
            items = await self._fallback.list_recent(limit=limit)
            return [replace(item, degraded=True) for item in items]

    async def _list_recent(self, *, limit: int) -> list[TenantNotification]:
        raw = await self._r.lrange(KEYS.tenant_notifications, 0, limit - 1)
        out = []
        for entry in raw:
            text = entry.decode() if isinstance(entry, bytes) else entry
            row = json.loads(text)
            out.append(
                TenantNotification(
                    id=row["id"],
                    kind=row["kind"],
                    subject=row["subject"],
                    message=row["message"],
                    severity=row["severity"],
                    created_at=float(row["created_at"]),
                )
            )
        return out


def tenant_notification_store(app_state: Any) -> TenantNotificationStore:
    """The app's notification store, creating a process-local one if nothing was wired."""
    store = getattr(app_state, "tenant_notifications", None)
    if store is None:
        store = InMemoryTenantNotificationStore()
        try:
            app_state.tenant_notifications = store
        except Exception:  # noqa: BLE001 — a read-only fake state object is not a failure
            pass
    return store
