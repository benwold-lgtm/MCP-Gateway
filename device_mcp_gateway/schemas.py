# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Response models for the UI-facing read endpoints.

These give the gateway's OpenAPI a real, named contract (`DeviceSummary`,
`OverviewResponse`, ...) so consumers — notably the UI repo — can generate typed
clients from /openapi.json instead of hand-maintaining mirror types.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from device_mcp_gateway.shared.registry_backend import DeviceConfig


class DeviceSummary(BaseModel):
    """Lean device projection for list/overview screens."""

    hostname: str
    base_url: str
    transport: str
    reachable: bool
    pod_active: bool
    last_check: float | None = None
    rate_limit_rps: float | None = None

    @classmethod
    def from_config(cls, cfg: DeviceConfig) -> DeviceSummary:
        """Project a registry ``DeviceConfig`` to the summary shape — the single
        place this mapping lives, so adding a field is a one-line change here
        rather than an edit at every read endpoint (F-19)."""
        return cls(
            hostname=cfg.hostname,
            base_url=cfg.base_url,
            transport=cfg.transport,
            reachable=cfg.reachable,
            pod_active=cfg.pod_active,
            last_check=cfg.last_check or None,
            rate_limit_rps=cfg.rate_limit_rps,
        )


class DeviceDetail(DeviceSummary):
    """Full device projection for the single-device read — a superset of
    :class:`DeviceSummary` adding the fields a detail/diagnostic view needs."""

    spec_url: str | None = None
    spec_hash: str | None = None
    auth_type: str | None = None
    spawn_error: str | None = None
    worker_id: str | None = None
    # Bumps whenever a spec change mutated the tool set (F-41); poll to detect a
    # change and re-list tools.
    tools_revision: int = 0

    @classmethod
    def from_config(cls, cfg: DeviceConfig) -> DeviceDetail:
        return cls(
            hostname=cfg.hostname,
            base_url=cfg.base_url,
            transport=cfg.transport,
            reachable=cfg.reachable,
            pod_active=cfg.pod_active,
            last_check=cfg.last_check or None,
            rate_limit_rps=cfg.rate_limit_rps,
            spec_url=cfg.spec_url,
            spec_hash=cfg.spec_hash,
            auth_type=cfg.auth_type,
            spawn_error=cfg.spawn_error,
            worker_id=cfg.worker_id,
            tools_revision=cfg.tools_revision,
        )


class DeviceListResponse(BaseModel):
    devices: list[DeviceSummary]


class DeviceMutationResult(BaseModel):
    """Response for a register/update write: the write-time envelope plus the full
    resulting device, so a client gets the resource back without a follow-up GET."""

    status: str  # "registered" | "updated"
    provisioning: bool  # F-11: pod still spawning in the background when True
    device: DeviceDetail


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
    tools_revision: int = 0
    spawn_error: str | None = None
    breaker: BreakerState


class ToolChangeRecord(BaseModel):
    """The most recent tool-set change for a device — what was added/removed/
    changed when its upstream OpenAPI spec last mutated, and whether that was
    backwards-breaking for clients calling the old shape (F-41)."""

    tools_revision: int
    at: float  # unix timestamp the change was observed
    added: list[str] = []
    removed: list[str] = []
    changed: list[str] = []
    breaking: bool = False
    breaking_reasons: list[str] = []


class ToolsDiffResponse(BaseModel):
    """Tool-set change governance for a device. ``last_change`` is ``null`` when no
    change has been observed since registration (the tool set is as first
    generated). ``tools_revision`` is the device's current monotonic revision —
    poll it to detect a change, then read ``last_change`` to see what moved."""

    hostname: str
    tools_revision: int
    last_change: ToolChangeRecord | None = None


class WhoAmIResponse(BaseModel):
    """The authenticated caller's own identity and effective authorization, so a UI/BFF
    can gate views on the **gateway's** scopes rather than maintaining a parallel role
    model (ADR-0007). ``scopes`` is sorted for a stable response."""

    subject: str
    scopes: list[str]
    auth_method: str
