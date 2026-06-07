# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for the async rate limiter (S2 finding F4).

Replaces slowapi (which made blocking Redis calls on the event loop). The limiter
is fully async; the Redis backend shares limits across replicas; the key func
trusts X-Forwarded-For only behind a trusted proxy.
"""

from types import SimpleNamespace

import pytest
import fakeredis.aioredis

from device_mcp_gateway.ratelimit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    client_ip_key_func,
    parse_limit,
)


def _req(forwarded=None, peer="10.0.0.1"):
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


# --- limit spec parsing -----------------------------------------------------


def test_parse_limit_variants():
    assert parse_limit("300/minute") == (300, 60)
    assert parse_limit("5/second") == (5, 1)
    assert parse_limit("10/hours") == (10, 3600)  # plural accepted


def test_parse_limit_invalid():
    for bad in ("abc/minute", "10/fortnight", "10"):
        with pytest.raises(ValueError):
            parse_limit(bad)


# --- client IP key function -------------------------------------------------


def test_trust_proxy_uses_leftmost_forwarded_ip():
    key = client_ip_key_func(trust_proxy=True)
    assert key(_req(forwarded="203.0.113.5, 70.0.0.1")) == "203.0.113.5"


def test_trust_proxy_falls_back_to_peer():
    key = client_ip_key_func(trust_proxy=True)
    assert key(_req(forwarded=None, peer="10.0.0.9")) == "10.0.0.9"


def test_untrusted_ignores_forwarded_header():
    key = client_ip_key_func(trust_proxy=False)
    assert key(_req(forwarded="1.2.3.4", peer="10.0.0.1")) == "10.0.0.1"


# --- in-memory limiter ------------------------------------------------------


@pytest.mark.asyncio
async def test_in_memory_allows_then_blocks():
    limiter = InMemoryRateLimiter()
    assert (await limiter.hit("k", 2, 60))[0] is True
    assert (await limiter.hit("k", 2, 60))[0] is True
    allowed, retry = await limiter.hit("k", 2, 60)
    assert allowed is False
    assert retry > 0


@pytest.mark.asyncio
async def test_in_memory_keys_are_independent():
    limiter = InMemoryRateLimiter()
    assert (await limiter.hit("a", 1, 60))[0] is True
    assert (await limiter.hit("b", 1, 60))[0] is True  # different key, own bucket


# --- Redis limiter (fakeredis) ----------------------------------------------


@pytest.mark.asyncio
async def test_redis_limiter_allows_then_blocks():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter = RedisRateLimiter(r)
    assert (await limiter.hit("k", 2, 60))[0] is True
    assert (await limiter.hit("k", 2, 60))[0] is True
    allowed, retry = await limiter.hit("k", 2, 60)
    assert allowed is False
    assert retry > 0


@pytest.mark.asyncio
async def test_redis_limiter_shared_across_instances():
    # Two limiter instances on the same Redis simulate two gateway replicas:
    # the counter is shared.
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    a, b = RedisRateLimiter(r), RedisRateLimiter(r)
    assert (await a.hit("k", 2, 60))[0] is True
    assert (await b.hit("k", 2, 60))[0] is True
    assert (await a.hit("k", 2, 60))[0] is False  # third hit blocked regardless of replica


# --- real Redis: cross-replica sharing for real -----------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_limiter_shared_on_real_redis(real_redis):
    a, b = RedisRateLimiter(real_redis), RedisRateLimiter(real_redis)
    assert (await a.hit("rk", 3, 60))[0] is True
    assert (await b.hit("rk", 3, 60))[0] is True
    assert (await a.hit("rk", 3, 60))[0] is True
    blocked, retry = await b.hit("rk", 3, 60)
    assert blocked is False
    assert 0 < retry <= 60
