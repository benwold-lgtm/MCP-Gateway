# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 slice 5 — the standing-consent self-issue frequency tracker, in isolation.

A self-issued grant has no per-instance human approval, so a subject self-issuing very often
is the signal worth flagging — same shape as `breakglass.py`'s reactivation-frequency counter,
deliberately a separate small tracker (see `support_grants.py`'s module comment for why). This
proves the tracker itself; `test_support_requests.py` proves the route wires it to the audit
event and the tenant-notification store once the threshold is crossed.
"""

from __future__ import annotations

import pytest

from device_mcp_gateway.support_grants import (
    InMemorySelfIssueActivityTracker,
    RedisSelfIssueActivityTracker,
    self_issue_activity_tracker,
)

pytestmark = pytest.mark.asyncio


class _DeadRedis:
    def pipeline(self, transaction=True):
        raise ConnectionError("redis is down")


async def test_the_count_increments_on_each_self_issue():
    tracker = InMemorySelfIssueActivityTracker()
    first = await tracker.record("op1", window_seconds=3600)
    second = await tracker.record("op1", window_seconds=3600)
    third = await tracker.record("op1", window_seconds=3600)

    assert (first.count_in_window, second.count_in_window, third.count_in_window) == (1, 2, 3)


async def test_two_subjects_are_counted_independently():
    tracker = InMemorySelfIssueActivityTracker()
    await tracker.record("op1", window_seconds=3600)
    await tracker.record("op1", window_seconds=3600)
    other = await tracker.record("op2", window_seconds=3600)

    assert other.count_in_window == 1


async def test_the_count_starts_clean_after_a_full_quiet_window():
    import asyncio

    tracker = InMemorySelfIssueActivityTracker()
    await tracker.record("op1", window_seconds=1)
    await asyncio.sleep(1.2)  # window fully elapsed
    activity = await tracker.record("op1", window_seconds=1)

    assert activity.count_in_window == 1


async def test_redis_tracker_counts_one_subject_across_replicas(real_redis):
    a = RedisSelfIssueActivityTracker(real_redis)
    b = RedisSelfIssueActivityTracker(real_redis)

    await a.record("op1", window_seconds=3600)
    activity = await b.record("op1", window_seconds=3600)

    assert activity.count_in_window == 2


async def test_redis_tracker_window_slides_and_expires(real_redis):
    tracker = RedisSelfIssueActivityTracker(real_redis)
    await tracker.record("op1", window_seconds=1)
    import asyncio as _asyncio

    await _asyncio.sleep(1.2)
    activity = await tracker.record("op1", window_seconds=1)

    assert activity.count_in_window == 1  # the earlier count expired, not accumulated


async def test_a_dead_redis_degrades_to_process_local_rather_than_losing_the_signal():
    tracker = RedisSelfIssueActivityTracker(_DeadRedis())
    activity = await tracker.record("op1", window_seconds=3600)

    assert activity.count_in_window == 1
    assert activity.degraded is True


async def test_the_accessor_lazily_attaches_one_instance_per_app_state():
    from types import SimpleNamespace

    state = SimpleNamespace()
    first = self_issue_activity_tracker(state)
    second = self_issue_activity_tracker(state)
    assert first is second
    await first.record("op1", window_seconds=3600)
    activity = await second.record("op1", window_seconds=3600)
    assert activity.count_in_window == 2
