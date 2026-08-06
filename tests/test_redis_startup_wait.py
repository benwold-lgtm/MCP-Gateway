# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Startup waits for Redis instead of dying on the first command.

Found on a live cluster: workers exited non-zero on the first Redis connection failure at
startup, twice each, before anything worked. Kubelet backoff recovers from that, which is
why it was easy to miss — but it recovers by way of a stack trace and a restart counter, and
those are the same signals an operator reads as "this deployment is broken". A start-order
race with Redis is not a crash and should not present as one.

The per-command retry budget is the wrong tool for this: it is deliberately ~2.5 s, sized so
a request caught mid-failover fails fast rather than blocking a caller. At startup nobody is
waiting on a response and the usual cause is that Redis has not finished starting.
"""

import asyncio

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from device_mcp_gateway.shared.redis_client import wait_for_redis


class _FlakyRedis:
    """Answers PING only after ``fail_times`` refusals, like a server still starting."""

    def __init__(self, fail_times: int):
        self.fail_times = fail_times
        self.pings = 0

    async def ping(self):
        self.pings += 1
        if self.pings <= self.fail_times:
            raise RedisConnectionError("Connection refused")
        return True


@pytest.mark.asyncio
async def test_it_waits_through_a_redis_that_is_still_starting():
    client = _FlakyRedis(fail_times=3)
    await wait_for_redis(client, {"redis": {"startup_timeout": 30}}, component="worker w1")
    assert client.pings == 4, "must keep retrying rather than exiting on the first refusal"


@pytest.mark.asyncio
async def test_a_redis_that_never_appears_still_fails():
    """Waiting must not become hanging — a genuinely dead Redis has to reach the exit code."""
    client = _FlakyRedis(fail_times=10_000)
    with pytest.raises(RuntimeError) as exc:
        await wait_for_redis(client, {"redis": {"startup_timeout": 1}}, component="worker w1")
    assert "unreachable" in str(exc.value)
    assert "startup_timeout" in str(exc.value), "the message must name the knob that changes this"
    assert client.pings > 1, "it should have retried before giving up"


@pytest.mark.asyncio
async def test_zero_timeout_restores_fail_fast():
    """Some deployments would rather die immediately than wait; that must stay available."""
    client = _FlakyRedis(fail_times=1)
    with pytest.raises(RedisConnectionError):
        await wait_for_redis(client, {"redis": {"startup_timeout": 0}}, component="gateway")
    assert client.pings == 1


@pytest.mark.asyncio
async def test_a_healthy_redis_is_not_delayed():
    """The common case must cost exactly one PING and no sleep."""
    client = _FlakyRedis(fail_times=0)
    started = asyncio.get_running_loop().time()
    await wait_for_redis(client, {}, component="gateway")
    assert client.pings == 1
    assert asyncio.get_running_loop().time() - started < 0.1


@pytest.mark.asyncio
async def test_the_wait_is_bounded_by_the_deadline_not_by_the_backoff():
    """Backoff doubles up to 5s, so the last sleep must be clamped to what remains rather
    than overshooting the timeout the operator configured."""
    client = _FlakyRedis(fail_times=10_000)
    started = asyncio.get_running_loop().time()
    with pytest.raises(RuntimeError):
        await wait_for_redis(client, {"redis": {"startup_timeout": 2}}, component="gateway")
    elapsed = asyncio.get_running_loop().time() - started
    assert elapsed < 4, f"overshot the 2s budget by too much ({elapsed:.1f}s)"
