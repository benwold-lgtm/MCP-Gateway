# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §4b / LR-46 — a curated device is never fetched from, at any of the five sites.

§4b said "an internal construction path", singular. Spec acquisition actually happens at five
call sites, four of which run on a timer forever, so the failure this file guards against is
not "the snapshot is never applied" — that would be obvious — but **the snapshot being applied
and then quietly replaced** on the next health cycle, spawn or cold-path fetch. A pinned
curated version silently becoming a live-fetched one is the drift §4a exists to prevent.

So the load-bearing tests here are the ones that run a site a *second* time and assert nothing
reached the network. A test that only checks registration would pass against a build where
four of the five sites still fetch.

The site inventory these track (`shared/spec_source.py` carries the same list):

    registry/server.py::_provision_device      via _discovery_for
    registry/server.py::_health_check_one      via _discovery_for
    registry/pod_supervisor.py::spawn          via _discovery_for  (LR-47)
    worker/runner.py::_fetch_spec              direct guard
    worker/health.py::_fetch_spec              direct guard
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from device_mcp_gateway.registry.curated_spec_source import CuratedSpecSource
from device_mcp_gateway.registry.models import DeviceProfile
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.shared.registry_backend import DeviceConfig
from device_mcp_gateway.shared.spec_source import (
    CuratedSpec,
    CuratedSpecInvalid,
    apply_curated_spec,
    resolve_spec_source,
    spec_hash,
)

DOCUMENT = json.dumps({"openapi": "3.0.3", "info": {"title": "Acme", "version": "1"}, "paths": {}})


def _Profile(cfg: DeviceConfig) -> DeviceProfile:
    """The real profile, not a stub.

    A hand-rolled double would have to guess which attributes each acquisition site touches,
    and a guess that is too small fails as an AttributeError in the test rather than telling
    you anything about the code — this project's standing lesson about fixtures simpler than
    production.
    """
    return DeviceProfile(config=cfg)


def _cfg(**over) -> DeviceConfig:
    fields = {"hostname": "dev1", "base_url": "https://dev1.local"}
    fields.update(over)
    return DeviceConfig(**fields)


# --- the decision ------------------------------------------------------------------------


def test_a_device_with_no_snapshot_is_fetched_live_as_before():
    assert resolve_spec_source(_cfg()) is None


def test_a_device_with_a_snapshot_resolves_to_it():
    assert resolve_spec_source(_cfg(curated_spec=DOCUMENT)) == CuratedSpec(DOCUMENT)


def test_an_empty_snapshot_is_not_a_snapshot():
    """`to_redis_hash` writes "" for an unset value, so a device that never had one comes back
    from Redis with the key present and empty. Treating that as a snapshot would strand the
    device with an unparseable spec it never had."""
    assert resolve_spec_source(_cfg(curated_spec="")) is None


def test_the_hash_is_recomputed_from_the_bytes_not_taken_on_trust():
    """§4b: the catalog's stored hash is what curation asserted; the gateway derives its own."""
    curated = CuratedSpec(DOCUMENT)
    import hashlib

    assert curated.content_sha256() == hashlib.sha256(DOCUMENT.encode()).hexdigest()


def test_a_curated_hash_is_on_the_same_scale_as_a_fetched_one():
    """Deliberately the same algorithm as `SpecService.fetch_spec`, not a better one: the value
    is compared against what a previous cycle stored, so changing it would make every existing
    device look changed exactly once and replace every pod in the fleet."""
    import hashlib

    parsed = json.loads(DOCUMENT)
    assert spec_hash(parsed) == hashlib.sha256(str(parsed).encode()).hexdigest()[:16]


def test_an_unparseable_snapshot_names_its_own_condition():
    """Distinct from a failed fetch on purpose: a fetch failure is usually transient, a
    snapshot that does not parse is inert and fails identically every cycle."""
    with pytest.raises(CuratedSpecInvalid):
        CuratedSpec("not json at all").parsed()
    with pytest.raises(CuratedSpecInvalid):
        CuratedSpec('["a", "list"]').parsed()


def test_applying_a_snapshot_does_not_claim_a_measurement():
    """`last_check` means "when did we last contact this device". A snapshot contacts nothing,
    and writing it would report a reachability measurement that never happened — the defect
    F-66 fixed for `reachable`."""
    profile = _Profile(_cfg(curated_spec=DOCUMENT, last_check=0.0))
    apply_curated_spec(profile, CuratedSpec(DOCUMENT))
    assert profile.config.last_check == 0.0
    assert profile.spec_data == json.loads(DOCUMENT)


def test_a_first_application_is_not_a_change():
    profile = _Profile(_cfg(curated_spec=DOCUMENT))
    assert apply_curated_spec(profile, CuratedSpec(DOCUMENT)) is False


def test_a_different_snapshot_is_a_change():
    profile = _Profile(_cfg(curated_spec=DOCUMENT, spec_hash="stale-hash"))
    assert apply_curated_spec(profile, CuratedSpec(DOCUMENT)) is True


# --- the embedded seam --------------------------------------------------------------------


def _registry() -> Registry:
    return Registry(config={"health_check_interval": 10})


def test_the_dispatcher_routes_a_curated_device_away_from_every_fetcher():
    reg = _registry()
    profile = _Profile(_cfg(curated_spec=DOCUMENT))
    assert isinstance(reg._discovery_for(profile), CuratedSpecSource)


def test_the_dispatcher_still_routes_openapi_and_mcp_as_before():
    """Both directions, because a change that sent everything to the curated source would
    pass a test asserting only the curated case."""
    reg = _registry()
    assert reg._discovery_for(_Profile(_cfg())) is reg._spec_service
    assert reg._discovery_for(_Profile(_cfg(upstream_kind="mcp"))) is reg._mcp_discovery


@pytest.mark.asyncio
async def test_the_curated_source_persists_only_the_hash():
    backend = AsyncMock()
    source = CuratedSpecSource(backend=backend)
    profile = _Profile(_cfg(curated_spec=DOCUMENT))

    await source.fetch_spec(profile)

    assert profile.spec_data == json.loads(DOCUMENT)
    backend.update_device_fields.assert_awaited_once()
    _, kwargs = backend.update_device_fields.await_args
    assert set(kwargs) == {"spec_hash"}, "last_check is a measurement and must not be written"


@pytest.mark.asyncio
async def test_an_unusable_snapshot_records_a_cause_an_operator_can_act_on():
    backend = AsyncMock()
    profile = _Profile(_cfg(curated_spec="{{{"))

    assert await CuratedSpecSource(backend=backend).fetch_spec(profile) is False
    assert "curated spec unusable" in (profile.config.spawn_error or "")
    backend.update_device_fields.assert_not_awaited()


# --- the sites that run on a timer ---------------------------------------------------------


@pytest.mark.asyncio
async def test_the_health_cycle_does_not_replace_a_snapshot():
    """THE test this file exists for. Registration applying the snapshot is easy; the failure
    is the health loop overwriting it on the next pass, which is what makes a pinned version
    stop being pinned."""
    reg = _registry()
    reg._spec_service.fetch_spec = AsyncMock(return_value=True)
    reg._mcp_discovery.fetch_spec = AsyncMock(return_value=True)
    profile = _Profile(_cfg(curated_spec=DOCUMENT))

    source = reg._discovery_for(profile)
    source._backend = AsyncMock()
    await source.fetch_spec(profile)
    await source.fetch_spec(profile)  # the second cycle is where the old behaviour bit

    assert profile.spec_data == json.loads(DOCUMENT)
    reg._spec_service.fetch_spec.assert_not_awaited()
    reg._mcp_discovery.fetch_spec.assert_not_awaited()


@pytest.mark.asyncio
async def test_spawn_asks_the_dispatcher_rather_than_the_openapi_service(monkeypatch):
    """LR-47. `spawn` reached for `self._spec_service` directly while both Registry sites went
    through `_discovery_for`, so an mcp device with no cached spec got the OPENAPI service —
    and a curated one would have been fetched from. Reachable: `_health_check_one` calls
    `spawn` guarded on `reachable and not pod_active`, never on `spec_data`.
    """
    reg = _registry()
    reg._spec_service.fetch_spec = AsyncMock(return_value=False)
    reg._mcp_discovery.fetch_spec = AsyncMock(return_value=False)
    profile = _Profile(_cfg(upstream_kind="mcp"))
    profile.spec_data = None

    await reg._pod_supervisor.spawn(profile)

    reg._mcp_discovery.fetch_spec.assert_awaited_once()
    reg._spec_service.fetch_spec.assert_not_awaited()


@pytest.mark.asyncio
async def test_spawn_does_not_fetch_for_a_curated_device():
    reg = _registry()
    reg._spec_service.fetch_spec = AsyncMock(return_value=False)
    reg._mcp_discovery.fetch_spec = AsyncMock(return_value=False)
    reg._curated_specs._backend = AsyncMock()
    reg._pod_supervisor._backend = AsyncMock()
    profile = _Profile(_cfg(curated_spec=DOCUMENT))

    await reg._pod_supervisor.spawn(profile)

    reg._spec_service.fetch_spec.assert_not_awaited()
    reg._mcp_discovery.fetch_spec.assert_not_awaited()
    assert profile.spec_data == json.loads(DOCUMENT)


# --- the distributed pair ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_worker_cold_path_serves_the_snapshot_without_fetching(monkeypatch):
    import device_mcp_gateway.worker.runner as runner_mod
    from device_mcp_gateway.worker.runner import DeviceWorker

    def _explode(*a, **k):  # pragma: no cover - asserting it is never reached
        raise AssertionError("the cold path fetched a curated device")

    monkeypatch.setattr(runner_mod, "build_guarded_client", _explode)
    worker = DeviceWorker(worker_id="w1", config={"registry": {}}, redis_client=None)

    assert await worker._fetch_spec(_cfg(curated_spec=DOCUMENT)) == json.loads(DOCUMENT)


@pytest.mark.asyncio
async def test_the_worker_health_loop_serves_the_snapshot_without_fetching():
    from device_mcp_gateway.worker.health import WorkerHealthLoop

    loop = WorkerHealthLoop(worker_id="w1", backend=None, redis_client=None)
    loop._upstream_for = lambda cfg: (_ for _ in ()).throw(AssertionError("health loop fetched"))

    assert await loop._fetch_spec(_cfg(curated_spec=DOCUMENT)) == json.loads(DOCUMENT)


# --- it survives the round trip -------------------------------------------------------------


def test_the_snapshot_survives_a_redis_round_trip():
    """A field that does not come back is a device that is curated until the first restart."""
    restored = DeviceConfig.from_redis_hash(_cfg(curated_spec=DOCUMENT).to_redis_hash())
    assert restored.curated_spec == DOCUMENT


def test_a_record_written_before_curation_existed_reads_as_uncurated():
    h = _cfg().to_redis_hash()
    del h["curated_spec"]
    assert DeviceConfig.from_redis_hash(h).curated_spec is None
