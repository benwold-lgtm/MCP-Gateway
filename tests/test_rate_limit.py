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
    parse_trusted_proxy_cidrs,
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
#
# Item 4 (third-party review): the key func used to take the LEFT-most X-Forwarded-For
# entry, which is whatever the client typed. nginx/traefik/k8s-ingress *append* to XFF
# rather than replace it, so a caller who sends their own header owns the left-most entry
# and therefore owns their rate-limit bucket — rotate the header, reset the counter.
# The resolution now walks XFF right-to-left through security.trusted_proxy_cidrs.

# Two disjoint trusted ranges so the tests can chain hops through both.
_TRUSTED = ["10.0.0.0/8", "192.168.10.0/24", "fd00:cafe::/32"]


def test_spoofed_xff_from_untrusted_peer_cannot_choose_its_own_bucket():
    """THE bypass this whole change exists to close.

    An attacker connecting DIRECTLY to the gateway (skipping the proxy entirely) sends a
    fully fabricated multi-entry XFF. Their TCP peer address is untrusted, so the walk must
    stop immediately: not one byte of their header may reach the rate-limit key. Under the
    old left-most implementation this returned "1.2.3.4".
    """
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    attacker = "198.51.100.7"
    assert key(_req(forwarded="1.2.3.4, 5.6.7.8, 10.0.0.5", peer=attacker)) == attacker
    # ...and rotating the header does not move them to a fresh bucket.
    for spoof in ("9.9.9.9", "203.0.113.1, 10.0.0.9", "10.0.0.1", ""):
        assert key(_req(forwarded=spoof, peer=attacker)) == attacker


def test_spoofed_xff_cannot_smuggle_extra_entries_past_a_real_proxy():
    """The other half of the bypass: the attacker IS behind the trusted proxy.

    The proxy appends the attacker's real IP, so XFF is "<attacker junk>, <real client IP>".
    The walk consumes only the trusted proxy hop and stops at the real client IP — the
    entries the attacker prepended are never reached.
    """
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    resolved = key(_req(forwarded="1.2.3.4, 5.6.7.8, 203.0.113.5", peer="10.0.0.5"))
    assert resolved == "203.0.113.5"


def test_legitimate_chain_resolves_the_real_client_behind_the_proxy():
    """Forward direction: a genuine LB→ingress→gateway chain still yields the real client."""
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    # peer = ingress pod (10/8); XFF = "<client>, <outer LB>" — both trusted hops popped.
    assert key(_req(forwarded="203.0.113.5, 192.168.10.7", peer="10.0.0.5")) == "203.0.113.5"
    # Single trusted hop.
    assert key(_req(forwarded="203.0.113.5", peer="10.0.0.5")) == "203.0.113.5"


def test_ipv6_trusted_hop_and_client():
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    assert key(_req(forwarded="2001:db8::1", peer="fd00:cafe::5")) == "2001:db8::1"
    # An IPv4-mapped IPv6 peer must match the IPv4 CIDR it really is (::ffff:10.0.0.5).
    assert key(_req(forwarded="203.0.113.5", peer="::ffff:10.0.0.5")) == "203.0.113.5"


def test_every_entry_trusted_falls_back_to_peer():
    """No untrusted hop anywhere in the chain — no client can be identified, so key on the
    socket peer rather than on a proxy address the header happened to name."""
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    assert key(_req(forwarded="10.0.0.6, 192.168.10.7", peer="10.0.0.5")) == "10.0.0.5"


def test_trust_proxy_falls_back_to_peer_without_header():
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    assert key(_req(forwarded=None, peer="10.0.0.9")) == "10.0.0.9"


def test_malformed_xff_entry_never_becomes_the_key():
    """A junk entry reached by the walk must not become an arbitrary attacker-chosen
    (and arbitrarily long) rate-limit key — fall back to the peer."""
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=_TRUSTED)
    assert key(_req(forwarded="not-an-ip", peer="10.0.0.5")) == "10.0.0.5"
    assert key(_req(forwarded="A" * 5000, peer="10.0.0.5")) == "10.0.0.5"


def test_untrusted_ignores_forwarded_header():
    key = client_ip_key_func(trust_proxy=False)
    assert key(_req(forwarded="1.2.3.4", peer="10.0.0.1")) == "10.0.0.1"


def test_trust_proxy_without_cidrs_degrades_to_peer_not_to_blind_trust():
    """Defense in depth behind the startup refusal: if a caller builds the key func with
    trust on but no trusted ranges, it must key on the peer, never on the header."""
    key = client_ip_key_func(trust_proxy=True, trusted_proxy_cidrs=[])
    assert key(_req(forwarded="1.2.3.4", peer="198.51.100.7")) == "198.51.100.7"


def test_invalid_cidr_is_rejected_loudly():
    for bad in (["10.0.0.0/8", "not-a-cidr"], ["10.0.0.0/33"], ["10.0.0.0/8", ""]):
        with pytest.raises(ValueError):
            parse_trusted_proxy_cidrs(bad)


def test_bare_ip_is_accepted_as_a_single_host_range():
    nets = parse_trusted_proxy_cidrs(["10.0.0.5", "fd00::1"])
    assert [str(n) for n in nets] == ["10.0.0.5/32", "fd00::1/128"]


# --- fail-closed startup gate -----------------------------------------------


def test_trust_proxy_without_trusted_cidrs_refuses_to_start(monkeypatch):
    """Config that would silently trust every XFF entry must not boot (item 4)."""
    from device_mcp_gateway.main import create_app

    monkeypatch.setenv("MCP_ADMIN_KEY", "test-admin-key")
    cfg = {"gateway": {"trust_proxy_headers": True}}
    with pytest.raises(RuntimeError, match="trust_proxy_headers"):
        create_app(override_config=cfg)


def test_trust_proxy_with_invalid_cidr_refuses_to_start(monkeypatch):
    from device_mcp_gateway.main import create_app

    monkeypatch.setenv("MCP_ADMIN_KEY", "test-admin-key")
    cfg = {
        "gateway": {"trust_proxy_headers": True},
        "security": {"trusted_proxy_cidrs": ["10.0.0.0/8", "nonsense"]},
    }
    with pytest.raises(RuntimeError, match="trusted_proxy_cidrs"):
        create_app(override_config=cfg)


def test_trust_proxy_with_cidrs_starts_and_wires_the_key_func(monkeypatch):
    from device_mcp_gateway.main import create_app

    monkeypatch.setenv("MCP_ADMIN_KEY", "test-admin-key")
    cfg = {
        "gateway": {"trust_proxy_headers": True},
        "security": {"trusted_proxy_cidrs": ["10.0.0.0/8"]},
    }
    app = create_app(override_config=cfg)  # must not raise
    assert app.state.rate_limit_key(_req(forwarded="203.0.113.5", peer="10.0.0.5")) == "203.0.113.5"


def test_trust_proxy_off_does_not_require_cidrs(monkeypatch):
    """The default posture (no proxy) must stay zero-config."""
    from device_mcp_gateway.main import create_app

    monkeypatch.setenv("MCP_ADMIN_KEY", "test-admin-key")
    app = create_app(override_config={"gateway": {"trust_proxy_headers": False}})
    assert app.state.rate_limit_key(_req(forwarded="1.2.3.4", peer="10.0.0.1")) == "10.0.0.1"


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


@pytest.mark.asyncio
async def test_redis_limiter_key_always_has_ttl_no_immortal_key():
    # #9: the very first hit must leave the key with an expiry. The old code set EXPIRE
    # as a separate call only on count==1, so a crash/failed EXPIRE left a TTL-less key
    # that throttled the client forever; the INCR+EXPIRE-NX MULTI/EXEC can't.
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await RedisRateLimiter(r).hit("k", 5, 60)
    assert await r.ttl("rl:k") > 0


@pytest.mark.asyncio
async def test_redis_limiter_does_not_refresh_window():
    # Fixed window: EXPIRE ... NX must not push the expiry out on later hits, or a steady
    # stream of requests would keep the bucket alive forever (a sliding window).
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter = RedisRateLimiter(r)
    await limiter.hit("k", 5, 60)
    await r.expire("rl:k", 30)  # simulate the window having partly elapsed
    await limiter.hit("k", 5, 60)
    assert await r.ttl("rl:k") <= 30  # NOT bumped back to 60


@pytest.mark.asyncio
async def test_redis_limiter_heals_a_key_left_without_ttl():
    # Defense in depth: a key that somehow lost its TTL (a legacy immortal key) gets one
    # re-applied on the next hit rather than throttling forever.
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await r.set("rl:k", 3)  # no expiry
    assert await r.ttl("rl:k") == -1
    await RedisRateLimiter(r).hit("k", 5, 60)
    assert await r.ttl("rl:k") > 0


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
