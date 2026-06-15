# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for the leader-elected reconciler and XAUTOCLAIM call recovery (SRE #1/#2).

A worker death used to leave its devices dark forever: recovery relied on the dead
worker restarting with the same WORKER_ID (the K8s pod name changes, so it never
did) and nothing republished the assignment. The reconciler detects devices whose
claim lease has lapsed and republishes their assignment; XAUTOCLAIM recovers tool
calls the dead worker read but never acked.
"""

import json

import pytest
import fakeredis.aioredis

from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend
from device_mcp_gateway.worker.runner import DeviceWorker

# grace_cycles=1 here so these mechanics-focused tests reassign on the first sweep;
# the multi-sweep hysteresis (default 2) has its own tests below (F-62).
CONFIG = {"registry": {"health_check_interval": 30, "reconcile_interval": 5, "reconcile_orphan_grace_cycles": 1}}


def _shared_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _worker(worker_id, redis):
    return DeviceWorker(worker_id=worker_id, config=CONFIG, redis_client=redis)


class _RecordingBackend(MemoryRegistryBackend):
    """In-memory backend that records published assignments.

    Lets the reconciler's logic be unit-tested against fakeredis (which exercises
    the claim-lease semantics) without the fakeredis hash byte-key quirk that
    breaks RedisRegistryBackend.get_device. The real RedisRegistryBackend path is
    covered end-to-end in test_integration_redis.py.
    """

    def __init__(self):
        super().__init__()
        self.assignments: list[tuple[str, str]] = []

    async def publish_assignment(self, action: str, hostname: str) -> None:
        self.assignments.append((action, hostname))


# --- Leadership -------------------------------------------------------------


@pytest.mark.asyncio
async def test_only_one_worker_leads():
    r = _shared_redis()
    a, b = _worker("A", r), _worker("B", r)
    assert await a._acquire_leadership(60) is True
    assert await b._acquire_leadership(60) is False  # A already leads
    assert await r.get("reconciler:leader") == "A"


@pytest.mark.asyncio
async def test_leadership_is_sticky_for_holder():
    r = _shared_redis()
    a = _worker("A", r)
    assert await a._acquire_leadership(60) is True
    # Re-acquiring our own leadership refreshes it rather than failing.
    assert await a._acquire_leadership(60) is True


# --- Reconcile sweep --------------------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_reassigns_orphaned_device():
    """A device left pod_active by a dead worker, with no live claim, is healed:
    stale ownership cleared and an 'assign' republished."""
    r = _shared_redis()
    backend = _RecordingBackend()
    await backend.set_device(
        "dev1", DeviceConfig(hostname="dev1", base_url="http://dev1", pod_active=True, worker_id="dead-worker")
    )
    worker = _worker("live", r)
    worker._backend = backend

    # No claim:dev1 exists (the dead worker's lease lapsed).
    assert await r.get("claim:dev1") is None

    await worker._reconcile_once()

    cfg = await backend.get_device("dev1")
    assert cfg.pod_active is False  # stale ownership cleared
    assert cfg.worker_id is None
    assert ("assign", "dev1") in backend.assignments


@pytest.mark.asyncio
async def test_reconcile_skips_device_with_live_claim():
    """A device a live worker still owns (claim present) must not be reassigned."""
    r = _shared_redis()
    backend = _RecordingBackend()
    await backend.set_device(
        "dev1", DeviceConfig(hostname="dev1", base_url="http://dev1", pod_active=True, worker_id="live")
    )
    worker = _worker("live", r)
    worker._backend = backend
    await r.set("claim:dev1", "live", ex=60)  # live owner

    await worker._reconcile_once()

    assert backend.assignments == []
    cfg = await backend.get_device("dev1")
    assert cfg.pod_active is True  # untouched


@pytest.mark.asyncio
async def test_reconcile_ignores_missing_config():
    """A hostname listed but with no config (raced deregistration) is skipped, not crashed on."""
    r = _shared_redis()

    class _GhostBackend(_RecordingBackend):
        async def list_hostnames(self):
            return ["ghost"]  # listed, but get_device returns None

    backend = _GhostBackend()
    worker = _worker("live", r)
    worker._backend = backend

    await worker._reconcile_once()  # must not raise
    assert backend.assignments == []


# --- Lease-flap hysteresis (F-62) -------------------------------------------


def _worker_grace(redis, grace):
    cfg = {"registry": {"health_check_interval": 30, "reconcile_orphan_grace_cycles": grace}}
    return DeviceWorker(worker_id="live", config=cfg, redis_client=redis)


async def _orphaned_backend(host="dev1"):
    backend = _RecordingBackend()
    await backend.set_device(
        host, DeviceConfig(hostname=host, base_url=f"http://{host}", pod_active=True, worker_id="dead-worker")
    )
    return backend


@pytest.mark.asyncio
async def test_hysteresis_defers_reassignment_until_grace_met():
    """With grace=2 a device seen orphaned on ONE sweep is not yet reassigned — it
    must persist across consecutive sweeps, so a transient lapse self-heals (F-62)."""
    r = _shared_redis()
    backend = await _orphaned_backend()
    worker = _worker_grace(r, grace=2)
    worker._backend = backend

    await worker._reconcile_once()  # sweep 1: missed once (1/2) — defer
    assert backend.assignments == []  # NOT reassigned yet
    cfg = await backend.get_device("dev1")
    assert cfg.pod_active is True  # ownership untouched while we wait

    await worker._reconcile_once()  # sweep 2: missed twice (2/2) — reassign
    assert ("assign", "dev1") in backend.assignments
    cfg = await backend.get_device("dev1")
    assert cfg.pod_active is False and cfg.worker_id is None


@pytest.mark.asyncio
async def test_hysteresis_resets_when_claim_reappears():
    """A transient lapse must not accumulate: if the owner refreshes its claim
    between sweeps, the orphan streak resets and no reassignment happens (F-62)."""
    r = _shared_redis()
    backend = await _orphaned_backend()
    worker = _worker_grace(r, grace=2)
    worker._backend = backend

    await worker._reconcile_once()  # sweep 1: 1/2 missed
    assert backend.assignments == []

    await r.set("claim:dev1", "owner-recovered", ex=60)  # owner came back (e.g. after a GC pause)
    await worker._reconcile_once()  # sweep 2: live claim → streak cleared
    assert backend.assignments == []
    assert worker._orphan_miss_counts.get("dev1") is None  # streak forgotten

    await r.delete("claim:dev1")  # lapses again later
    await worker._reconcile_once()  # counts as the FIRST miss again, not the second
    assert backend.assignments == []  # still deferred — flap did not trigger a reassign


@pytest.mark.asyncio
async def test_reassignment_increments_churn_metric():
    """Each reassignment bumps the churn counter so flapping is alertable (F-62)."""
    from device_mcp_gateway import metrics

    r = _shared_redis()
    backend = await _orphaned_backend()
    worker = _worker_grace(r, grace=1)  # reassign immediately
    worker._backend = backend

    before = metrics.reconciler_reassignments_total._value.get()
    await worker._reconcile_once()
    assert ("assign", "dev1") in backend.assignments
    assert metrics.reconciler_reassignments_total._value.get() == before + 1


@pytest.mark.asyncio
async def test_orphan_counts_pruned_for_vanished_devices():
    """A device that disappears mid-streak (deregistered) drops out of the miss map
    so it can't grow without bound."""
    r = _shared_redis()

    hostnames = ["dev1"]

    class _ShrinkingBackend(_RecordingBackend):
        async def list_hostnames(self):
            return list(hostnames)

    backend = _ShrinkingBackend()
    await backend.set_device(
        "dev1", DeviceConfig(hostname="dev1", base_url="http://dev1", pod_active=True, worker_id="dead")
    )
    worker = _worker_grace(r, grace=3)
    worker._backend = backend

    await worker._reconcile_once()  # 1/3 — recorded
    assert worker._orphan_miss_counts.get("dev1") == 1

    hostnames.clear()  # device deregistered
    await worker._reconcile_once()
    assert "dev1" not in worker._orphan_miss_counts  # pruned, not leaked


# --- XAUTOCLAIM recovery of stranded calls ----------------------------------


@pytest.mark.asyncio
async def test_reclaim_pending_recovers_unacked_call():
    """A call a dead worker read (into the PEL) but never acked is reclaimed and
    dispatched by the new owner (SRE #1)."""
    r = _shared_redis()
    stream, group = "device:dev1:calls", "workers-dev1"
    await r.xgroup_create(stream, group, id="0", mkstream=True)

    # Dead worker reads the call into its PEL but never acks it.
    await r.xadd(
        stream,
        {"session_id": "s1", "request_id": "req1", "message": json.dumps({"id": 1, "method": "tools/list"})},
    )
    await r.xreadgroup(group, "dead-worker", {stream: ">"}, count=10)
    pending_before = await r.xpending(stream, group)
    assert pending_before["pending"] == 1

    # New owner with a 0ms idle threshold reclaims immediately.
    worker = _worker("live", r)
    worker._reclaim_min_idle_ms = 0

    class _FakePod:
        async def call_tool(self, message):
            return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": []}}

    worker._pods["dev1"] = _FakePod()

    import asyncio

    await worker._reclaim_pending("dev1", stream, group, asyncio.Semaphore(worker._max_calls_per_device))

    # The reclaimed entry is dispatched on a task; let it run to completion.

    for _ in range(20):
        await asyncio.sleep(0.01)
        if await r.get("result:req1"):
            break

    assert await r.get("result:req1") == "1"  # call executed + marked handled
    pending_after = await r.xpending(stream, group)
    assert pending_after["pending"] == 0  # acked, no longer stranded


@pytest.mark.asyncio
async def test_reclaim_pending_tolerates_empty_stream():
    """No pending entries → no-op, no error."""
    import asyncio

    r = _shared_redis()
    stream, group = "device:dev2:calls", "workers-dev2"
    await r.xgroup_create(stream, group, id="0", mkstream=True)
    worker = _worker("live", r)
    worker._reclaim_min_idle_ms = 0
    await worker._reclaim_pending("dev2", stream, group, asyncio.Semaphore(5))  # must not raise
