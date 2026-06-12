# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Outbound retry/backoff + periodic-loop jitter (Tier-1 F-05 / F-44 / F-61).

Three coordinated resilience primitives:

  - **F-05 bounded retries with full-jitter backoff** on *idempotent* outbound ops
    (GET reachability, GET spec/discovery, GET tool calls). A single transient blip
    (dropped connection, one 503) no longer fails the whole call. Non-idempotent
    methods (POST/PUT/PATCH/DELETE) are **never** auto-retried — a timed-out mutation
    may already have applied, so a blind retry could double-execute.
  - **F-44 upstream rate-limit awareness** — on a 429, honor `Retry-After` (capped;
    if the device asks for longer than we'll wait, stop and surface the 429 rather
    than sleeping the whole call). 429/502/503/504 are the retryable statuses.
  - **F-61 jitter** — `jittered()` de-correlates steady-state periodic loops so a
    fleet doesn't reconverge in lock-step after a Redis flap / cold start.

`random` here is for load de-correlation, not security — hence the `# nosec B311`.
"""

from __future__ import annotations

import asyncio
import email.utils
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

# Only HTTP-safe (idempotent, side-effect-free) methods are auto-retried.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Transient upstream statuses worth a bounded retry on a safe method.
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


def jittered(interval: float, ratio: float = 0.2) -> float:
    """Return ``interval`` ± up to ``ratio`` of jitter, to de-sync periodic loops (F-61)."""
    if interval <= 0:
        return interval
    delta = interval * ratio
    return interval + random.uniform(-delta, delta)  # nosec B311 — de-correlation, not crypto


def full_jitter(attempt: int, base: float, cap: float) -> float:
    """AWS-style full-jitter backoff: ``uniform(0, min(cap, base * 2**attempt))`` (F-05)."""
    return random.uniform(0, min(cap, base * (2**attempt)))  # nosec B311 — backoff, not crypto


def parse_retry_after(value: str | None) -> float | None:
    """Parse a ``Retry-After`` header (delta-seconds or HTTP-date) into seconds (F-44).

    Returns None when absent/unparseable; never negative.
    """
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    return max(0.0, dt.timestamp() - time.time())


@dataclass
class RetryPolicy:
    """Bounded retry budget. Kept small to avoid amplifying load on a struggling upstream."""

    max_retries: int = 2
    base_delay: float = 0.2
    max_delay: float = 5.0
    respect_retry_after: bool = True

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None) -> "RetryPolicy":
        reg = (cfg or {}).get("registry", {})
        return cls(
            max_retries=int(reg.get("max_retries", 2)),
            base_delay=float(reg.get("retry_base_delay", 0.2)),
            max_delay=float(reg.get("retry_max_delay", 5.0)),
        )


async def send_with_retry(
    send: Callable[[], Awaitable[httpx.Response]],
    *,
    method: str,
    policy: RetryPolicy,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_retry: Callable[[int, str], None] | None = None,
) -> httpx.Response:
    """Invoke ``send()`` with bounded, jittered retries — idempotent methods only (F-05/F-44).

    Retries transient transport errors/timeouts and ``RETRYABLE_STATUS`` responses for
    safe methods. On a 429 with ``Retry-After`` longer than ``max_delay`` it stops and
    returns the 429 (don't hold the call open hammering a throttled API). Non-safe
    methods get a single attempt; their result/exception passes straight through.

    ``on_retry(attempt, reason)`` is called just before each backoff sleep (for metrics).
    """
    retryable = method.upper() in SAFE_METHODS
    attempt = 0
    while True:
        try:
            resp = await send()
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            if not retryable or attempt >= policy.max_retries:
                raise
            if on_retry:
                on_retry(attempt, type(exc).__name__)
            await sleep(full_jitter(attempt, policy.base_delay, policy.max_delay))
            attempt += 1
            continue

        if retryable and attempt < policy.max_retries and resp.status_code in RETRYABLE_STATUS:
            delay: float | None = None
            if policy.respect_retry_after and resp.status_code == 429:
                ra = parse_retry_after(resp.headers.get("retry-after"))
                if ra is not None:
                    if ra > policy.max_delay:
                        return resp  # device wants a longer pause than we'll hold the call
                    delay = ra
            if delay is None:
                delay = full_jitter(attempt, policy.base_delay, policy.max_delay)
            if on_retry:
                on_retry(attempt, f"status_{resp.status_code}")
            await sleep(delay)
            attempt += 1
            continue

        return resp


__all__ = [
    "SAFE_METHODS",
    "RETRYABLE_STATUS",
    "jittered",
    "full_jitter",
    "parse_retry_after",
    "RetryPolicy",
    "send_with_retry",
]
