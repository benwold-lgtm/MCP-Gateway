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


class BreakerState(BaseModel):
    """Per-pod circuit-breaker state. Only readable when the pod is in-process
    (embedded mode); in distributed mode the pod runs on a worker, so the gateway
    reports ``available: false`` with a note."""

    available: bool
    state: str | None = None  # closed | open | half-open
    fail_counter: int | None = None
    fail_max: int | None = None
    reset_timeout: int | None = None
    note: str | None = None


class DeviceDiagnostics(BaseModel):
    """ "Why is my device down?" — a single read combining registry status, the
    last check, spec/manifest state, the spawn error, and the circuit breaker
    (F-52)."""

    hostname: str
    mode: str
    base_url: str
    spec_url: str | None = None
    transport: str
    reachable: bool
    pod_active: bool
    worker_id: str | None = None
    last_check: float | None = None
    last_check_age_seconds: float | None = None
    spec_hash: str | None = None
    has_manifest: bool
    tool_count: int
    spawn_error: str | None = None
    breaker: BreakerState
