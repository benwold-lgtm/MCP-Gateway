# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""F-66 / FMEA D10 — a default must not read as a measurement.

Found on a live cluster: a device whose pod never spawned served ``reachable: true``
indefinitely, next to a ``spawn_error`` saying it had failed, with a ``last_check`` that
aged without bound (observed 150s → 190s across a 40s wait). Nothing was lying on
purpose — nothing had *written* anything. ``WorkerHealthLoop.run_forever(assigned)``
iterates only a worker's **assigned** devices, and a device whose spawn fails is never
assigned, so the only writer of ``reachable`` in distributed mode never runs for it. The
dataclass defaults (``reachable=True``, ``last_check=time.time()``) were served forever.

Two properties are pinned here, because fixing only the first leaves the hole open:

1. The spawn path **records the contact it already made**. It reached out for a spec and
   got nothing — that is a reachability measurement, and it is the only one this device
   will ever get.
2. The defaults **claim nothing**. ``reachable=False`` / ``last_check=0.0`` mean "not
   established" and "never checked", which the response models already render as a null
   ``last_check`` / ``last_check_age_seconds``. So "never checked" stays distinguishable
   from "checked and dead" without the tri-state that would have broken the API shape.

The third shape of the same bug in a fortnight — ``EXPIRE`` on a missing key creates
nothing, ``HSET`` on a missing key creates something, a default reads as a measurement.
All three are "the code assumed something had happened that hadn't."
"""

from __future__ import annotations

import fakeredis.aioredis
import httpx
import pytest

import device_mcp_gateway.worker.runner as runner_mod
from device_mcp_gateway.schemas import DeviceDetail, DeviceSummary
from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend
from device_mcp_gateway.worker.runner import DeviceWorker

CONFIG = {"registry": {"health_check_interval": 30}}
HOST = "never-spawned"


def _worker(redis):
    """The same memory-backend worker the other distributed tests use — fakeredis 2.36
    returns bytes from ``hgetall``, which ``from_redis_hash`` cannot parse. The Redis
    round-trip is pinned separately on the real-Redis tier at the bottom of this file."""
    from device_mcp_gateway.core.backoff import RetryPolicy

    w = DeviceWorker(worker_id="w1", config=CONFIG, redis_client=redis)
    w._backend = MemoryRegistryBackend()
    w._retry_policy = RetryPolicy()  # built in run(), which these tests don't call
    return w


@pytest.fixture
def unreachable_upstream(monkeypatch):
    """Every outbound hop refuses to connect — the device that is simply not there."""

    def _client(**kwargs):
        def _refuse(request):
            raise httpx.ConnectError("connection refused", request=request)

        return httpx.AsyncClient(transport=httpx.MockTransport(_refuse))

    monkeypatch.setattr(runner_mod, "build_guarded_client", _client)


@pytest.mark.asyncio
async def test_a_device_whose_pod_never_spawns_is_not_reported_reachable(unreachable_upstream):
    """The cluster scenario, end to end: register, fail to spawn, read the record back.

    Deliberately driven through ``_spawn_pod`` rather than by asserting on the defaults,
    because the defaults were only half the bug: the record is *written* during the failed
    spawn, and a write that carried no reachability verdict would leave the stale one
    standing even after the defaults were fixed.
    """
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    w = _worker(r)
    await w._backend.set_device(HOST, DeviceConfig(hostname=HOST, base_url="http://gone.local"))

    await w._spawn_pod(HOST)

    cfg = await w._backend.get_device(HOST)
    assert cfg.spawn_error and "No spec available" in cfg.spawn_error
    assert cfg.pod_active is False
    assert cfg.reachable is False, "a device nothing could contact must not read as reachable"
    assert cfg.last_check > 0, "the failed contact is a measurement and must be timestamped"
    # The device is never assigned, so the health loop will never revisit it. That is the
    # whole point: the verdict above is the only one it will ever get.
    assert HOST not in w._assigned


@pytest.mark.asyncio
async def test_a_rejected_spec_does_not_blame_the_network(monkeypatch):
    """Reached but unusable is not the same fact as unreachable.

    The device answered; we then refused its spec (F-09 bounds). Scoring that unreachable
    would send an operator to check the network for what is a spec fault, and
    ``spawn_error`` already carries the real reason.
    """
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    w = _worker(r)
    await w._backend.set_device(HOST, DeviceConfig(hostname=HOST, base_url="http://answers.local"))

    async def _spec(cfg):
        return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}

    async def _reject(*args, **kwargs):
        # Stands in for the translation pool rather than the translator: the real call
        # crosses a process boundary, so a locally-defined stub could not be pickled to it.
        raise ValueError("spec exceeds the configured bound")

    monkeypatch.setattr(w, "_fetch_spec", _spec)
    monkeypatch.setattr(runner_mod, "run_translation", _reject)

    before = (await w._backend.get_device(HOST)).last_check
    await w._spawn_pod(HOST)

    cfg = await w._backend.get_device(HOST)
    assert cfg.spawn_error and "rejected" in cfg.spawn_error
    assert cfg.pod_active is False
    assert cfg.reachable is True, "the device answered — the spec is what failed"
    # Not just "true": the contact has to have been *recorded*. Asserting the flag alone
    # would pass on the old optimistic default without anything having been written.
    assert cfg.last_check > before, "the successful contact must be timestamped"


@pytest.mark.asyncio
async def test_a_cache_hit_spawn_claims_no_measurement_it_did_not_make():
    """Spawning from a cached manifest never touches the device, so it reports nothing.

    The opposite failure to F-66 and just as wrong: writing ``reachable=True`` here would
    be a fresh truth claim backed by a manifest that could be an hour old. The device is
    assigned once the pod is up, so the health loop takes the first real measurement.
    """
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    w = _worker(r)
    await w._backend.set_device(HOST, DeviceConfig(hostname=HOST, base_url="http://cached.local"))
    await w._backend.set_manifest(HOST, {"hostname": HOST, "tools": [], "resources": [], "prompts": []}, ttl=60)

    await w._spawn_pod(HOST)
    try:
        cfg = await w._backend.get_device(HOST)
        assert cfg.pod_active is True
        assert cfg.last_check == 0, "nothing contacted the device, so nothing may be timestamped"
        assert HOST in w._assigned, "the health loop owns it now and will take the first measurement"
    finally:
        await w._kill_pod(HOST)


def test_a_fresh_record_reports_never_checked_rather_than_healthy():
    """The defaults themselves, and how they surface through the response models."""
    cfg = DeviceConfig(hostname=HOST, base_url="http://new.local")

    assert cfg.reachable is False
    assert cfg.last_check == 0.0

    # `last_check: null` is what makes this distinguishable from "checked and found dead"
    # without a tri-state — the API shape is unchanged, `reachable` is still a bool.
    assert DeviceSummary.from_config(cfg).last_check is None
    detail = DeviceDetail.from_config(cfg)
    assert detail.last_check is None
    assert detail.reachable is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_stored_reachable_without_a_check_does_not_survive_the_round_trip(real_redis):
    """The invariant, over a real hash: ``reachable`` cannot outlive its measurement.

    Its writers set both fields in one call, so this is belt-and-braces rather than a
    repair — but ``from_redis_hash`` is the one place every distributed read passes
    through, and it is where a future writer's truth-claim-with-nothing-behind-it gets
    caught. Real Redis rather than fakeredis on purpose: fakeredis does not decode hash
    reads, so this round trip cannot be exercised there at all.
    """
    from device_mcp_gateway.shared.keys import KEYS
    from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend

    backend = RedisRegistryBackend(real_redis)
    await backend.set_device(HOST, DeviceConfig(hostname=HOST, base_url="http://gone.local"))
    # Exactly what a pre-fix record looks like: an optimistic flag, no check behind it.
    await real_redis.hset(KEYS.device_config(HOST), mapping={"reachable": "True", "last_check": "0"})

    cfg = await backend.get_device(HOST)
    assert cfg.reachable is False
    assert cfg.last_check == 0.0
