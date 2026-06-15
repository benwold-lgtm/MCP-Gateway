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
from fastapi import HTTPException

from device_mcp_gateway.ratelimit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    client_ip_key_func,
    parse_limit,
    principal_key_func,
    rate_limit,
    rate_limit_principal,
)


def _req(forwarded=None, peer="10.0.0.1"):
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


def _app_req(limiter, subject=None, peer="10.0.0.1", forwarded=None):
    """A request wired like a live one: app.state limiter/key-func + request.state
    principal (as authenticate_request would have set it)."""
    principal = SimpleNamespace(subject=subject) if subject is not None else None
    app = SimpleNamespace(
        state=SimpleNamespace(rate_limiter=limiter, rate_limit_key=client_ip_key_func(trust_proxy=False))
    )
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(
        app=app,
        state=SimpleNamespace(principal=principal),
        headers=headers,
        client=SimpleNamespace(host=peer),
    )


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


# --- per-principal key + quota (F-16) ---------------------------------------


def test_principal_key_uses_subject():
    assert principal_key_func(_app_req(InMemoryRateLimiter(), subject="alice")) == "alice"


def test_principal_key_anonymous_when_unauthenticated():
    # No principal stashed (anonymous / unauthenticated) collapses to one bucket.
    assert principal_key_func(_app_req(InMemoryRateLimiter(), subject=None)) == "anonymous"


@pytest.mark.asyncio
async def test_principal_limit_caps_one_identity_across_ips():
    """A single principal can't multiply its budget by spreading calls over many
    source IPs — the gap the IP-only limiter misses (F-16)."""
    limiter = InMemoryRateLimiter()
    dep = rate_limit_principal("2/minute", "messages")
    await dep(_app_req(limiter, subject="alice", peer="10.0.0.1"))
    await dep(_app_req(limiter, subject="alice", peer="10.0.0.2"))  # different IP, same identity
    with pytest.raises(HTTPException) as ei:
        await dep(_app_req(limiter, subject="alice", peer="10.0.0.3"))
    assert ei.value.status_code == 429
    assert "Retry-After" in ei.value.headers


@pytest.mark.asyncio
async def test_principal_limits_are_per_identity():
    limiter = InMemoryRateLimiter()
    dep = rate_limit_principal("1/minute", "messages")
    await dep(_app_req(limiter, subject="alice"))
    await dep(_app_req(limiter, subject="bob"))  # bob has his own bucket — not blocked by alice
    with pytest.raises(HTTPException):
        await dep(_app_req(limiter, subject="bob"))  # bob now over his own quota


@pytest.mark.asyncio
async def test_principal_and_ip_limits_compose_independently():
    """Per-IP and per-principal limits use disjoint key namespaces, so they don't
    share a counter — each enforces its own full budget on the same request."""
    limiter = InMemoryRateLimiter()
    ip_dep = rate_limit("5/minute", "messages")
    pr_dep = rate_limit_principal("5/minute", "messages")
    req = _app_req(limiter, subject="alice", peer="10.0.0.1")
    for _ in range(5):
        await ip_dep(req)
        await pr_dep(req)
    # If they collided on one key they'd have tripped at 5 combined; instead each
    # reaches its own 5 and the 6th of each trips separately.
    with pytest.raises(HTTPException):
        await ip_dep(req)
    with pytest.raises(HTTPException):
        await pr_dep(req)


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
