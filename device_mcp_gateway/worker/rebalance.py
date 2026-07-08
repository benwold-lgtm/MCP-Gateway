# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Per-worker load rebalancing on scale-out (F-07).

Extracted from the DeviceWorker god-object. Reads worker state through the
worker reference at call time — see ``worker/dispatch.py`` for why. The shed
path calls back into ``worker._kill_pod`` (pod lifecycle stays on the worker).
"""

from __future__ import annotations

import asyncio
import math
from typing import TYPE_CHECKING

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.core.backoff import jittered

if TYPE_CHECKING:  # pragma: no cover
    from device_mcp_gateway.worker.runner import DeviceWorker


class Rebalancer:
    """Sheds a worker's excess devices so new/idle workers pick up load."""

    def __init__(self, worker: "DeviceWorker") -> None:
        self._w = worker

    async def live_worker_count(self) -> int:
        """Number of workers with a live heartbeat (membership alone overstates it)."""
        w = self._w
        live = 0
        for wid in await w._r.smembers("workers:active"):
            if await w._r.exists(f"worker:{wid}:heartbeat"):
                live += 1
        return max(live, 1)

    async def rebalance_target(self) -> tuple[int, int]:
        """Per-worker device target = ceil(total devices / live workers), and the
        live-worker count. With this target the maximum fleet imbalance is one
        device, and at least one worker is always below target when a device needs
        a home (pigeonhole) — so declining at/over target can't starve placement."""
        total = int(await self._w._r.scard("devices:all"))
        live = await self.live_worker_count()
        return math.ceil(total / live), live

    async def decline_assignment(self, hostname: str) -> bool:
        """Should this worker refuse to take ``hostname`` right now? (F-07)

        Two reasons: (a) we just shed it ourselves (cooldown marker is ours) — let
        another worker take it instead of immediately re-grabbing it; (b) we're
        already at/over the per-worker target while other workers exist — bias
        placement toward an under-target worker. A declined assignment is left
        unclaimed; the leader reconciler republishes it next sweep, so it still
        lands (on an under-target worker)."""
        w = self._w
        if not w._rebalance_enabled:
            return False
        if (await w._r.get(f"rebalance:cooldown:{hostname}")) == w._id:
            logger.debug(f"Declining {hostname}: in our own rebalance cooldown")
            return True
        target, live = await self.rebalance_target()
        if live > 1 and len(w._assigned) >= target:
            logger.debug(f"Declining {hostname}: at/over target ({len(w._assigned)}/{target})")
            return True
        return False

    async def rebalance_loop(self) -> None:
        """Per-worker (not leader-gated) loop: shed devices over the target so a
        scaled-out/idle worker actually picks up load (F-07)."""
        w = self._w
        while not w._stop_event.is_set():
            try:
                if w._rebalance_enabled:
                    await self.rebalance_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Rebalance cycle failed")
            await asyncio.sleep(jittered(w._reconcile_interval))  # F-61: de-sync fleet rebalancing

    async def rebalance_once(self) -> None:
        w = self._w
        target, live = await self.rebalance_target()
        if live <= 1:
            return  # nothing to balance onto
        excess = len(w._assigned) - target
        if excess <= 0:
            return
        # Shed the excess down to target. Sheds are independent across workers and
        # sum to the global excess, which fits the under-target capacity — so this
        # converges (typically in one cycle) without over-shedding.
        for hostname in list(w._assigned)[:excess]:
            await self.shed_device(hostname, target)

    async def shed_device(self, hostname: str, target: int) -> None:
        """Release a device so another worker can take it. A short cooldown marks it
        ours so we don't immediately re-claim our own shed device."""
        w = self._w
        await w._r.set(f"rebalance:cooldown:{hostname}", w._id, ex=w._claim_ttl)
        await w._kill_pod(hostname)  # releases the claim + marks pod inactive
        if w._backend:
            await w._backend.publish_assignment("assign", hostname)
        metrics.rebalance_shed_total.inc()
        logger.info(f"Rebalance: shed {hostname} (had {len(w._assigned) + 1}, target {target})")
