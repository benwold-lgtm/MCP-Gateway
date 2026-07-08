# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Leader-elected orphaned-device reconciler (SRE #1/#2, F-62).

Extracted from the DeviceWorker god-object. Reads worker state (`_backend`,
`_orphan_miss_counts`, config scalars) through the worker reference at call time
— see ``worker/dispatch.py`` for why (tests and startup mutate those attributes
directly). ``DeviceWorker`` keeps thin ``_reconcile_once``-style wrappers.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.core.backoff import jittered

if TYPE_CHECKING:  # pragma: no cover
    from device_mcp_gateway.worker.runner import DeviceWorker

# Leader lock: exactly one worker runs the reconciler sweep at a time (SRE #1/#2).
_RECONCILER_LOCK = "reconciler:leader"


class Reconciler:
    """Periodically heals orphaned devices; one worker leads at a time."""

    def __init__(self, worker: "DeviceWorker") -> None:
        self._w = worker

    async def reconcile_loop(self) -> None:
        """Periodically heal orphaned devices. One worker leads at a time.

        Pre-fix, a worker death left its devices dark forever: recovery relied on
        the dead worker restarting with the same WORKER_ID (in K8s the pod name
        changes, so it never did), and nothing republished the assignment. This
        sweep makes failure self-healing without depending on the dead worker.
        """
        w = self._w
        lock_ttl = max(w._reconcile_interval * 2, 60)
        while not w._stop_event.is_set():
            try:
                is_leader = await self.acquire_leadership(lock_ttl)
                # Export leadership so an alert can fire when no worker holds it
                # (orphaned-device recovery stalled) — sum across workers == 1 (F-14).
                metrics.reconciler_leader.set(1 if is_leader else 0)
                if is_leader:
                    await self.reconcile_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Reconciler cycle failed")
            await asyncio.sleep(jittered(w._reconcile_interval))  # F-61: de-sync leader elections

    async def acquire_leadership(self, ttl: int) -> bool:
        """Claim/refresh the reconciler leader lock. Only the leader sweeps.

        SET NX to take it; if we already hold it, refresh the TTL so leadership is
        sticky while we're alive but lapses soon after we die, letting another
        worker take over.
        """
        w = self._w
        key = _RECONCILER_LOCK
        if await w._r.set(key, w._id, nx=True, ex=ttl):
            return True
        if (await w._r.get(key)) == w._id:
            await w._r.expire(key, ttl)
            return True
        return False

    async def reconcile_once(self) -> None:
        """Republish 'assign' for every device with no live claim.

        A live owner keeps claim:{hostname} refreshed via its heartbeat; when a
        worker dies the lease lapses within ~claim_ttl. A lapsed claim therefore
        means no worker is running the pod — so we clear the stale pod_active/
        worker_id the dead owner left in Redis and republish an assignment for a
        live worker to pick up (its _spawn_pod re-acquires the now-free claim).

        Idempotent: a device that already has a live claim is skipped, and
        _spawn_pod re-checks the claim, so a duplicate assign can't double-run a pod.
        Also re-homes devices that went unreachable (and were unassigned), so they
        recover once the target comes back.
        """
        w = self._w
        assert w._backend is not None, "backend not initialised — call run() first"
        hostnames = await w._backend.list_hostnames()
        reassigned = 0
        for hostname in hostnames:
            if await w._r.get(f"claim:{hostname}") is not None:
                # A live worker holds the claim — clear any orphan streak so a past
                # transient lapse doesn't count toward a future reassignment (F-62).
                w._orphan_miss_counts.pop(hostname, None)
                continue
            # No live claim. Apply hysteresis: only reassign once the device has been
            # seen orphaned across enough consecutive sweeps that a transient lapse
            # (GC pause / Redis stall under the grace window) has been ruled out (F-62).
            misses = w._orphan_miss_counts.get(hostname, 0) + 1
            w._orphan_miss_counts[hostname] = misses
            if misses < w._orphan_grace_cycles:
                logger.info(
                    f"Device {hostname} has no live claim (sweep {misses}/{w._orphan_grace_cycles}); "
                    "deferring reassignment in case the lapse is transient (F-62)"
                )
                continue
            cfg = await w._backend.get_device(hostname)
            if cfg is None:
                w._orphan_miss_counts.pop(hostname, None)
                continue  # raced with deregistration
            if cfg.pod_active or cfg.worker_id:
                # Ownership left stale by a dead worker — make Redis reflect reality.
                await w._backend.update_device_fields(hostname, pod_active=False, worker_id=None)
            await w._backend.publish_assignment("assign", hostname)
            metrics.reconciler_reassignments_total.inc()  # churn signal — alert on rate (F-62)
            w._orphan_miss_counts.pop(hostname, None)  # streak consumed; start fresh
            reassigned += 1
            logger.info(f"Reconciler reassigned orphaned device {hostname} after {misses} missed sweep(s)")
        # Drop streaks for devices that no longer exist so the map can't grow unbounded.
        w._orphan_miss_counts = {h: n for h, n in w._orphan_miss_counts.items() if h in hostnames}
        if reassigned:
            logger.info(f"Reconciler reassigned {reassigned} orphaned device(s) this cycle")
        await self.prune_dead_workers()

    async def prune_dead_workers(self) -> None:
        """Drop crashed workers (no live heartbeat) from workers:active (SRE #7/#8).

        A worker that crashes never deregisters, so the set otherwise grows without
        bound and overstates the fleet. Live workers re-assert membership each
        heartbeat, so a worker pruned during its brief startup race re-registers.
        """
        w = self._w
        for wid in await w._r.smembers("workers:active"):
            if not await w._r.exists(f"worker:{wid}:heartbeat"):
                await w._r.srem("workers:active", wid)
                logger.info(f"Pruned dead worker {wid} from workers:active")
