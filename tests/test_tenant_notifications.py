# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 slice 5 / the confirmed ADR-0023 gap — the durable tenant-notification store, in
isolation. `test_break_glass_activity.py` and `test_support_requests.py` prove the two real
producers wire into this; this proves the store itself: newest-first ordering, the retention
cap, and the Redis-backed store's degrade-to-in-process fallback.
"""

from __future__ import annotations

import pytest

from device_mcp_gateway.tenant_notifications import (
    InMemoryTenantNotificationStore,
    RedisTenantNotificationStore,
    tenant_notification_store,
)

pytestmark = pytest.mark.asyncio


class _DeadRedis:
    """Every call raises — proves the degrade path without a real broken connection."""

    def pipeline(self, transaction=True):
        raise ConnectionError("redis is down")

    async def lrange(self, *a, **kw):
        raise ConnectionError("redis is down")


# --- InMemoryTenantNotificationStore -------------------------------------------------------


async def test_a_created_notification_round_trips():
    store = InMemoryTenantNotificationStore()
    note = await store.create(kind="break_glass.activated", subject="key:alice", message="m", severity="critical")

    [only] = await store.list_recent()
    assert only.id == note.id
    assert only.kind == "break_glass.activated"
    assert only.subject == "key:alice"
    assert only.message == "m"
    assert only.severity == "critical"
    assert only.degraded is False


async def test_list_recent_is_newest_first():
    store = InMemoryTenantNotificationStore()
    await store.create(kind="k", subject="s", message="first", severity="warning")
    await store.create(kind="k", subject="s", message="second", severity="warning")

    notes = await store.list_recent()
    assert [n.message for n in notes] == ["second", "first"]


async def test_list_recent_respects_the_limit():
    store = InMemoryTenantNotificationStore()
    for i in range(5):
        await store.create(kind="k", subject="s", message=str(i), severity="warning")

    notes = await store.list_recent(limit=2)
    assert [n.message for n in notes] == ["4", "3"]


async def test_the_retention_cap_drops_the_oldest():
    store = InMemoryTenantNotificationStore(max_retained=3)
    for i in range(5):
        await store.create(kind="k", subject="s", message=str(i), severity="warning")

    notes = await store.list_recent(limit=10)
    assert [n.message for n in notes] == ["4", "3", "2"]


# --- RedisTenantNotificationStore -----------------------------------------------------------


async def test_redis_store_round_trips(real_redis):
    store = RedisTenantNotificationStore(real_redis)
    await store.create(kind="k", subject="op1", message="hello", severity="warning")

    [only] = await store.list_recent()
    assert only.subject == "op1"
    assert only.message == "hello"
    assert only.degraded is False


async def test_redis_store_caps_via_ltrim(real_redis):
    store = RedisTenantNotificationStore(real_redis, max_retained=3)
    for i in range(5):
        await store.create(kind="k", subject="s", message=str(i), severity="warning")

    notes = await store.list_recent(limit=10)
    assert [n.message for n in notes] == ["4", "3", "2"]


async def test_a_dead_redis_degrades_to_process_local_rather_than_losing_the_signal():
    store = RedisTenantNotificationStore(_DeadRedis())
    note = await store.create(kind="k", subject="s", message="m", severity="warning")
    assert note.degraded is True

    notes = await store.list_recent()
    assert notes[0].degraded is True
    assert notes[0].message == "m"


# --- accessor ---------------------------------------------------------------------------


async def test_the_accessor_lazily_attaches_one_instance_per_app_state():
    from types import SimpleNamespace

    state = SimpleNamespace()
    first = tenant_notification_store(state)
    second = tenant_notification_store(state)
    assert first is second
    # and it is a real, usable store, not just an identity placeholder
    await first.create(kind="k", subject="s", message="m", severity="warning")
    assert len(await second.list_recent()) == 1
