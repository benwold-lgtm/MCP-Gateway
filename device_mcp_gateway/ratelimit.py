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

import time
from typing import Protocol

from fastapi import HTTPException, Request

_PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def parse_limit(spec: str) -> tuple[int, int]:
    """Parse "300/minute" → (300, 60). Accepts singular or plural periods."""
    count_str, _, period = spec.partition("/")
    seconds = _PERIODS.get(period.rstrip("s"))
    if seconds is None or not count_str.strip().isdigit():
        raise ValueError(f"Invalid rate limit spec: {spec!r}")
    return int(count_str), seconds


def client_ip_key_func(trust_proxy: bool):
    """Return a function mapping a request to its rate-limit client identity.

    Behind a trusted proxy/ingress, request.client.host is the proxy IP — so use
    the left-most X-Forwarded-For entry (the original client). When untrusted,
    key on the socket peer so a spoofed header can't change the bucket.
    """

    def _key(request: Request) -> str:
        if trust_proxy:
            xff = request.headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

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
        rkey = f"rl:{key}"
        count = await self._r.incr(rkey)
        if count == 1:
            # Only the request that created the key sets the window expiry.
            await self._r.expire(rkey, window)
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
