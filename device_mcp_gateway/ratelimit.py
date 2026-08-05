# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Async, optionally Redis-backed rate limiting (F4).

Replaces slowapi, whose `limits` storage layer runs synchronously — every check
made a blocking Redis call on the event loop — and whose async Redis backend
would require a second client library (coredis). This implementation is fully
async on the redis.asyncio client we already use:

  - InMemoryRateLimiter  — embedded mode / tests (per-process)
  - RedisRateLimiter      — distributed mode (shared across gateway replicas)

Both use a fixed window (INCR + EXPIRE). Fixed windows allow a small burst at
the boundary but are cheap (O(1), one round-trip) and correct across replicas,
which matters far more than boundary precision for coarse API limits.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Protocol, Sequence

from fastapi import HTTPException, Request
from loguru import logger
from device_mcp_gateway.shared.keys import KEYS

_PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_limit(spec: str) -> tuple[int, int]:
    """Parse "300/minute" → (300, 60). Accepts singular or plural periods."""
    count_str, _, period = spec.partition("/")
    seconds = _PERIODS.get(period.rstrip("s"))
    if seconds is None or not count_str.strip().isdigit():
        raise ValueError(f"Invalid rate limit spec: {spec!r}")
    return int(count_str), seconds


def parse_trusted_proxy_cidrs(values: Sequence[str]) -> list[_IPNetwork]:
    """Parse ``security.trusted_proxy_cidrs`` into networks, raising on anything invalid.

    A bare address is accepted as a single-host range (``10.0.0.5`` → ``10.0.0.5/32``) so
    an operator naming one ingress IP doesn't have to write the mask. Invalid entries raise
    rather than being skipped: a typo'd CIDR silently dropped from the trust set is exactly
    the kind of quiet mis-config that re-opens the header-spoofing hole it exists to close.
    """
    nets: list[_IPNetwork] = []
    for raw in values:
        text = str(raw).strip()
        try:
            # strict=False so "10.0.0.5/24" is read as its containing network rather than
            # rejected for having host bits set.
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid trusted proxy CIDR {raw!r}: {exc}") from exc
    return nets


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an address from a header entry or peer, or None if it isn't one.

    Mirrors the normalisation the outbound SSRF guard applies (``security/url_policy.py``):
    strip an IPv6 scope id, then unwrap an IPv4-mapped IPv6 address to the IPv4 it really
    is, so ``::ffff:10.0.0.5`` matches a ``10.0.0.0/8`` trust entry. Deliberately a separate
    implementation from that module — inbound peer trust and outbound egress policy are
    independent concerns that must be free to diverge, even though the mechanics rhyme.
    """
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _is_trusted(text: str, nets: Sequence[_IPNetwork]) -> bool:
    ip = _parse_ip(text)
    if ip is None:
        return False
    return any(ip.version == net.version and ip in net for net in nets)


def client_ip_key_func(trust_proxy: bool, trusted_proxy_cidrs: Sequence[str] | None = None):
    """Return a function mapping a request to its rate-limit client identity.

    Behind a proxy/ingress ``request.client.host`` is the proxy, so the real client has to
    come from ``X-Forwarded-For``. The left-most entry — the obvious choice, and what this
    used to do — is **attacker-controlled**: nginx, traefik and the k8s ingresses *append*
    to XFF rather than replace it, so a caller who sends their own header owns the left-most
    value and therefore owns their rate-limit bucket. Rotating the header reset the counter
    and poisoned IP-based audit attribution (third-party review, item 4).

    So resolution walks the chain from the end you can actually vouch for. Starting at the
    TCP peer, entries are popped off the *right* of XFF for as long as each hop is inside
    ``trusted_proxy_cidrs``; the first hop that isn't is the client. An attacker who skips
    the proxy fails at the very first step — their peer is untrusted, so the walk never
    starts and their header is never read. An attacker behind the proxy only gets the one
    entry the proxy itself appended (their real address); whatever they prepended sits to
    the left of it and is never reached.

    Falls back to the socket peer when there is no header, when every hop is trusted (no
    client to identify), or when the resolved hop isn't a valid address. With trust enabled
    but no configured ranges it degrades to peer-only and warns — never to blind trust. That
    is the second line: ``create_app`` refuses to start in that configuration outright.
    """
    nets = parse_trusted_proxy_cidrs(trusted_proxy_cidrs or [])
    if trust_proxy and not nets:
        logger.warning(
            "trust_proxy_headers is enabled but no security.trusted_proxy_cidrs are configured — "
            "X-Forwarded-For will be IGNORED and rate limits keyed on the socket peer, because "
            "trusting the header without knowing which hops are yours lets any client choose its "
            "own rate-limit bucket."
        )

    def _key(request: Request) -> str:
        peer = request.client.host if request.client else "unknown"
        if not trust_proxy or not nets:
            return peer
        xff = request.headers.get("x-forwarded-for")
        if not xff:
            return peer

        entries = [e.strip() for e in xff.split(",") if e.strip()]
        hop = peer
        # Pop from the right while the hop we just came from is infrastructure we own.
        while entries and _is_trusted(hop, nets):
            hop = entries.pop()
        # Fall back to the peer when the walk never started (untrusted peer — an attacker
        # who skipped the proxy), when every hop was ours so no client was identified, or
        # when the resolved hop isn't a valid address (a junk entry must never become an
        # arbitrary — and arbitrarily long — attacker-chosen bucket key).
        if _is_trusted(hop, nets) or _parse_ip(hop) is None:
            return peer
        return hop

    return _key


def principal_key_func(request: Request) -> str:
    """Map a request to its authenticated rate-limit identity (F-16).

    ``authenticate_request`` (rbac) stashes ``request.state.principal`` before any
    route dependency runs, so the per-principal limiter can key on the caller's
    ``subject``. Unauthenticated/anonymous callers collapse to one shared bucket.
    This dimension is orthogonal to the per-IP one: it caps a single identity even
    when spread across many source IPs (which the IP limiter alone would miss).
    """
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "subject", None)
    return subject or "anonymous"


class RateLimiter(Protocol):
    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Record a hit; return (allowed, retry_after_seconds)."""
        ...


class InMemoryRateLimiter:
    """Per-process fixed-window limiter for embedded mode and tests."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[float, int]] = {}

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        start, count = self._buckets.get(key, (now, 0))
        if now - start >= window:
            start, count = now, 0
        count += 1
        self._buckets[key] = (start, count)
        # Opportunistic prune so the dict can't grow without bound.
        if len(self._buckets) > 10_000:
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[0] < window}
        if count > limit:
            return False, int(window - (now - start)) + 1
        return True, 0


class RedisRateLimiter:
    """Fixed-window limiter shared across replicas via Redis."""

    def __init__(self, redis_client) -> None:
        self._r = redis_client

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        rkey = KEYS.ratelimit(key)
        # INCR + EXPIRE in one MULTI/EXEC so they execute as an atomic server-side unit.
        # The previous code set EXPIRE only on the first hit (count == 1) as a separate
        # call, so a crash or a failed EXPIRE between the two left a TTL-less key that
        # throttled the client forever (the "immortal key"). EXPIRE ... NX (Redis 7+)
        # sets the window only when the key has none — so it preserves the fixed window
        # (won't refresh a live TTL) AND re-applies a missing one on the next hit, making
        # a counted-but-unexpiring key impossible to persist.
        pipe = self._r.pipeline(transaction=True)
        pipe.incr(rkey)
        pipe.expire(rkey, window, nx=True)
        count, _ = await pipe.execute()
        if count > limit:
            ttl = await self._r.ttl(rkey)
            return False, ttl if ttl and ttl > 0 else window
        return True, 0


async def _enforce(limiter: RateLimiter, key: str, limit: int, window: int) -> None:
    """Record a hit on `key` and raise 429 (with Retry-After) if over the limit."""
    allowed, retry_after = await limiter.hit(key, limit, window)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


def rate_limit(spec: str, scope: str):
    """FastAPI dependency enforcing `spec` (e.g. "60/minute") per client IP for `scope`.

    Reads the active limiter and key function from app.state, so embedded vs
    distributed selection and proxy-trust config live in one place (create_app).
    """
    limit, window = parse_limit(spec)

    async def _dependency(request: Request) -> None:
        limiter: RateLimiter = request.app.state.rate_limiter
        client = request.app.state.rate_limit_key(request)
        await _enforce(limiter, f"{scope}:{client}", limit, window)

    return _dependency


def rate_limit_principal(spec: str, scope: str):
    """FastAPI dependency enforcing `spec` per authenticated principal for `scope` (F-16).

    Composes with (does not replace) the per-IP :func:`rate_limit` on the same route:
    an expensive call must satisfy *both* its per-IP and its per-identity budget, so
    neither one principal fanning out across many IPs nor many principals behind one
    NAT can evade their fair share. Reuses the same app.state limiter backend, so it
    is per-process in embedded mode and shared across replicas in distributed mode.
    Order this dependency after ``authenticate_request`` so the principal is resolved.
    """
    limit, window = parse_limit(spec)

    async def _dependency(request: Request) -> None:
        limiter: RateLimiter = request.app.state.rate_limiter
        subject = principal_key_func(request)
        await _enforce(limiter, f"principal:{scope}:{subject}", limit, window)

    return _dependency
