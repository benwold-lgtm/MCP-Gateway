# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 finding #11 — a device that loses its credential must say so.

Finding #9 gave the **cold** path a reason channel: a device that never spawned records
``No spec available for X (credential: ...)`` instead of pointing an operator at the
upstream. A device that spawned successfully and *then* lost its credential recorded
nothing at all — it went unreachable with an empty ``spawn_error``, and the reconciler
churned reassign/decline for as long as the secret was missing.

**Measured on the mcp-gw cluster before this was written**, by renaming the key inside a
mounted Kubernetes Secret under a running worker — no pod restart, no redeploy:

    14:23:56  key renamed in the Secret
    14:24:25  kubelet re-projected the volume; api-key gone from the worker's mount
    14:25:05  byref -> reachable=false, pod_active=false, spawn_error='' (empty)
    ...       empty for the next 9 minutes, across a full spec-poll interval

That timing is what locates the defect. ``spec_poll_interval`` is 300s and the state
flipped inside 40s, so the failure lands in ``_check_reachability`` — an MCP upstream
authenticates during ``initialize`` — and **not** in ``_fetch_spec``. A reason channel
added only to the spec path would not have touched the device the finding came from.

These tests deliberately drive the **real** ``ApiKeyAuth`` and the **real**
``MountedFilesResolver`` against a real (empty) directory. The thing being pinned is that
a resolver failure survives the trip through the auth handler, the MCP client and the
health loop's exception handling to reach the device record — and every one of those
layers is a place the previous version swallowed it. A stub resolver raising a chosen
exception would prove none of that, which is the whole lesson of this slice.

The live re-run after the fix is row C6 of the slice-3 verification matrix; this file is
the fast regression, not the proof.
"""

from __future__ import annotations

import fakeredis.aioredis
import pytest

from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.credentials.resolver import MountedFilesResolver
from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend
from device_mcp_gateway.worker.health import CREDENTIAL_REASON_MARKER, WorkerHealthLoop

HOST = "byref"
MISSING_REF = "secret://t-lab000000000001/devices/gone#api-key"


async def _loop_with_revoked_credential(tmp_path, *, pod_active: bool = True, spawn_error: str | None = None):
    """A worker whose device is by-reference and whose secret is not on disk.

    ``tmp_path`` is a real, empty directory, so the resolver takes its genuine
    "no secret at ..." path rather than one a test invented.
    """
    backend = MemoryRegistryBackend()
    await backend.set_device(
        HOST,
        DeviceConfig(
            hostname=HOST,
            base_url="http://byref.invalid/mcp",
            upstream_kind="mcp",
            pod_active=pod_active,
            reachable=True,
            spawn_error=spawn_error,
        ),
    )
    resolver = MountedFilesResolver(tmp_path, require_private=False)

    def _auth_for(cfg):
        auth = ApiKeyAuth(credential_ref=MISSING_REF)
        auth.configure_credentials(resolver)
        return auth

    loop = WorkerHealthLoop(
        worker_id="w1",
        backend=backend,
        redis_client=fakeredis.aioredis.FakeRedis(decode_responses=True),
        interval=30,
        spec_poll_interval=300,
        auth_provider=_auth_for,
    )
    return loop, backend


@pytest.mark.asyncio
async def test_a_revoked_credential_is_named_on_the_device_record(tmp_path):
    """The regression itself: unreachable is not enough, the record must say *why*."""
    loop, backend = await _loop_with_revoked_credential(tmp_path)

    await loop._check_device(HOST)

    cfg = await backend.get_device(HOST)
    assert cfg.reachable is False
    assert cfg.spawn_error, "a device that lost its credential recorded no reason at all"
    assert MISSING_REF in cfg.spawn_error, cfg.spawn_error
    # The operator-facing point: the message names the SECRET, not the device's upstream.
    assert "no secret at" in cfg.spawn_error, cfg.spawn_error


@pytest.mark.asyncio
async def test_the_reason_is_rewritten_on_later_cycles_not_only_the_first(tmp_path):
    """``pod_active`` is already False by the second cycle, and the old code keyed the
    whole write off it — so every cycle after the first wrote nothing. The cluster sits in
    this state, not the first one: the reconciler re-assigns a device it cannot spawn, so
    an operator looking at the fleet is almost always looking at cycle N, not cycle 1."""
    loop, backend = await _loop_with_revoked_credential(tmp_path, pod_active=False)

    await loop._check_device(HOST)

    cfg = await backend.get_device(HOST)
    assert cfg.spawn_error and MISSING_REF in cfg.spawn_error


@pytest.mark.asyncio
async def test_reachability_semantics_are_unchanged(tmp_path):
    """Option A's boundary, pinned. Recording the reason must not redefine ``reachable``
    or unassign differently — that question is a separate change, and a test that lets it
    drift in here would hide it."""
    loop, backend = await _loop_with_revoked_credential(tmp_path)

    await loop._check_device(HOST)

    cfg = await backend.get_device(HOST)
    assert cfg.reachable is False  # as before the fix: the probe failed, so it is False
    assert cfg.pod_active is False  # as before the fix


@pytest.mark.asyncio
async def test_our_own_reason_is_cleared_when_the_device_recovers(tmp_path, monkeypatch):
    """A stale cause is its own defect — the cluster showed byref recovering ~5 minutes
    after the secret came back, and a reason left behind would outlive the fault."""
    stale = f"Device unavailable for {HOST} {CREDENTIAL_REASON_MARKER}no secret at '{MISSING_REF}')"
    loop, backend = await _loop_with_revoked_credential(tmp_path, spawn_error=stale)

    async def _reachable(_cfg):
        return True

    monkeypatch.setattr(loop, "_check_reachability", _reachable)

    await loop._check_device(HOST)

    cfg = await backend.get_device(HOST)
    assert cfg.spawn_error is None, "a credential reason outlived the fault that caused it"


@pytest.mark.asyncio
async def test_a_spawn_path_reason_is_not_clobbered(tmp_path, monkeypatch):
    """The clear is scoped to reasons this loop wrote. A spawn_error describing a
    different attempt belongs to the spawn path and is not ours to discard."""
    theirs = "Pod spawn refused: image pull backoff"
    loop, backend = await _loop_with_revoked_credential(tmp_path, spawn_error=theirs)

    async def _reachable(_cfg):
        return True

    monkeypatch.setattr(loop, "_check_reachability", _reachable)

    await loop._check_device(HOST)

    cfg = await backend.get_device(HOST)
    assert cfg.spawn_error == theirs
