# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Per-device downstream rate limiter (token bucket)."""

import asyncio
import time


class TokenBucket:
    """Asyncio token bucket for per-device downstream rate limiting.

    Args:
        rate: Maximum requests per second.
        max_wait: Maximum seconds acquire() will block before raising
                  asyncio.TimeoutError. None means unlimited (block forever).
    """

    def __init__(self, rate: float, max_wait: float | None = None) -> None:
        self._rate = rate
        self._tokens = float(rate)
        self._last = time.monotonic()
        self._max_wait = max_wait

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def tokens(self) -> float:
        now = time.monotonic()
        refilled = min(self._rate, self._tokens + (now - self._last) * self._rate)
        return round(refilled, 3)

    async def acquire(self) -> None:
        """Consume one token, waiting until one is available.

        Raises:
            asyncio.TimeoutError: if max_wait is set and the wait would exceed it.
        """
        waited = 0.0
        while True:
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            sleep_for = (1.0 - self._tokens) / self._rate
            if self._max_wait is not None and waited + sleep_for > self._max_wait:
                raise asyncio.TimeoutError(
                    f"Rate limit wait would exceed {self._max_wait}s " f"(rate={self._rate} rps)"
                )
            await asyncio.sleep(sleep_for)
            waited += sleep_for
