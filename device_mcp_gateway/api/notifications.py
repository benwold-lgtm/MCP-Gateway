# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The durable tenant-notification surface (ADR-0017 slice 5) — a read-only list a tenant
console will poll. Gated by `notifications:read`, not `support:administer`: reading this list
is passive fleet visibility, the same shape as `devices:read`, and a tenant admin should not
need to hold support-mechanism-administration authority just to see it.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from device_mcp_gateway.rbac import SCOPE_NOTIFICATIONS_READ, require_scope
from device_mcp_gateway.tenant_notifications import tenant_notification_store

router = APIRouter(dependencies=[Depends(require_scope(SCOPE_NOTIFICATIONS_READ))])


@router.get("/notifications")
async def list_notifications(request: Request, limit: int = Query(50, ge=1, le=200)):
    notifications = await tenant_notification_store(request.app.state).list_recent(limit=limit)
    return {
        "notifications": [
            {
                "id": n.id,
                "kind": n.kind,
                "subject": n.subject,
                "message": n.message,
                "severity": n.severity,
                "created_at": n.created_at,
            }
            for n in notifications
        ]
    }
