# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Embedded-mode runtime models shared by the registry collaborators.

``DeviceProfile`` lives here (rather than in registry/server.py) so the
SpecService and PodSupervisor collaborators can depend on it without importing
the Registry — keeping the module graph acyclic after the F-12 decomposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.pods.device_pod import DevicePod
from device_mcp_gateway.shared.registry_backend import DeviceConfig


@dataclass
class DeviceProfile:
    """Runtime device state used only in embedded mode.

    Holds the DeviceConfig plus asyncio/pod references that cannot be
    serialised to Redis.
    """

    config: DeviceConfig
    auth: AbstractAuth | None = None
    spec_data: dict[str, Any] | None = None
    pod: DevicePod | None = None

    # Convenience pass-throughs so call-sites don't need to know about .config
    @property
    def hostname(self) -> str:
        return self.config.hostname

    @property
    def base_url(self) -> str:
        return self.config.base_url

    @property
    def spec_url(self) -> str | None:
        return self.config.spec_url

    @property
    def transport(self) -> str:
        return self.config.transport

    @property
    def rate_limit_rps(self) -> float | None:
        return self.config.rate_limit_rps

    @property
    def reachable(self) -> bool:
        return self.config.reachable

    @property
    def pod_active(self) -> bool:
        return self.config.pod_active

    @property
    def last_reachable_check(self) -> float:
        return self.config.last_check

    @property
    def spawn_error(self) -> str | None:
        return self.config.spawn_error

    @property
    def spec_hash(self) -> str | None:
        return self.config.spec_hash
