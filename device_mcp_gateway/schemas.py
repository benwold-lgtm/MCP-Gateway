# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Response models for the UI-facing read endpoints.

These give the gateway's OpenAPI a real, named contract (`DeviceSummary`,
`OverviewResponse`, ...) so consumers — notably the UI repo — can generate typed
clients from /openapi.json instead of hand-maintaining mirror types.
"""

from __future__ import annotations

from pydantic import BaseModel


class DeviceSummary(BaseModel):
    hostname: str
    base_url: str
    transport: str
    reachable: bool
    pod_active: bool
    last_check: float | None = None
    rate_limit_rps: float | None = None


class DeviceListResponse(BaseModel):
    devices: list[DeviceSummary]


class OverviewCounts(BaseModel):
    total: int
    active_pods: int
    reachable: int
    unreachable: int


class OverviewResponse(BaseModel):
    mode: str
    counts: OverviewCounts
    devices: list[DeviceSummary]
