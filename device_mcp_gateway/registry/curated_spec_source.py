# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The embedded spec source for a device carrying a curated snapshot (ADR-0020 §4b).

A third implementation of the ``fetch_spec(profile) -> bool`` contract that
``Registry._discovery_for`` already dispatches on, alongside ``SpecService`` (OpenAPI) and
``McpDiscovery`` (passthrough). Slotting curation in there rather than branching at each
caller is what makes provisioning, the health loop and pod spawn all inherit it — LR-46's
choke point, on the embedded side.

The name says fetch and it fetches nothing. That is the point: the contract is *"make the
device's spec available and say whether the tool set moved"*, which a snapshot answers
without touching the network. §4b's `_check_target_url` note applies here too — there is no
URL, so the SSRF guard is **inapplicable rather than skipped**, and the safety property it
enforces was satisfied once already, at curation time, by §4a's guarded fetch.

It lives in `registry/` and not in `shared/` because applying a snapshot persists the
recomputed hash, and only this side holds the backend. The *decision* — curated or live — is
in `shared/spec_source.py`, which is the part both planes must agree on.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from device_mcp_gateway.shared.registry_backend import AbstractRegistryBackend
from device_mcp_gateway.shared.spec_source import (
    CuratedSpecInvalid,
    apply_curated_spec,
    resolve_spec_source,
)


class CuratedSpecSource:
    """Applies a device's stored snapshot. Never reaches the network."""

    def __init__(self, *, backend: AbstractRegistryBackend) -> None:
        self._backend = backend

    async def fetch_spec(self, profile: Any) -> bool:
        curated = resolve_spec_source(profile.config)
        if curated is None:
            # Unreachable through `_discovery_for`, which only routes here when a snapshot
            # exists. Reachable if someone calls this source directly, so it answers "nothing
            # changed" rather than raising: a spec source that throws on a device with no
            # spec would turn a wiring mistake into a dead health loop.
            return False
        try:
            changed = apply_curated_spec(profile, curated)
        except CuratedSpecInvalid as exc:
            # Distinct from a failed fetch, and recorded as such. A fetch failure is usually
            # transient; a snapshot that does not parse is inert and will fail identically
            # every cycle until the version is re-curated, so the message has to name the
            # cause rather than read as an unreachable device.
            logger.error(f"Curated spec unusable for {profile.hostname}: {exc}")
            profile.config.spawn_error = f"curated spec unusable: {exc}"
            return False

        # Persist only the hash. `last_check` stays untouched — it means "when did we last
        # contact this device", and nothing was contacted (see `apply_curated_spec`).
        await self._backend.update_device_fields(profile.hostname, spec_hash=profile.config.spec_hash)
        if not changed:
            logger.debug(f"Curated spec applied for {profile.hostname}: hash={profile.config.spec_hash}")
        return changed
