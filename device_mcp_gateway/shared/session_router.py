# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""
SSE session registry and result routing via Redis pub/sub.

In distributed mode every gateway instance is stateless with respect to
SSE clients.  When a client opens a stream on Gateway A and a tool call
arrives at Gateway B, the result still reaches the client because:

  Worker → PUBLISH session:{id}:results <json-rpc-response>
         → Redis fan-out
         → Gateway A (subscribed to session:{id}:results) → SSE event

Session keys carry a TTL so abandoned sessions expire automatically.
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncGenerator

from loguru import logger

_SESSION_TTL = 86_400  # 24 h — refreshed periodically while the stream is active
_REFRESH_THROTTLE = 60.0  # min seconds between TTL refreshes on a busy stream


class _RefreshThrottle:
    """Permits an action at most once per `window` seconds (monotonic clock).

    Used to cap session-TTL refreshes: a busy SSE stream would otherwise issue
    one Redis EXPIRE per message. One refresh per minute keeps a 24 h TTL alive
    with negligible Redis traffic.
    """

    def __init__(self, window: float) -> None:
        self._window = window
        self._last = 0.0  # 0 → first call always fires

    def ready(self, now: float) -> bool:
        if now - self._last >= self._window:
            self._last = now
            return True
        return False


class SessionRouter:
    """Register SSE sessions and route results across gateway instances."""

    def __init__(self, redis_client: Any, pubsub_client: Any = None) -> None:
        self._r = redis_client
        # Long-lived SSE subscriptions each hold a connection for their whole
        # lifetime. Route them through a dedicated client/pool so they don't
        # exhaust the shared command pool (F3). Falls back to the command client
        # when no separate one is supplied.
        self._ps = pubsub_client if pubsub_client is not None else redis_client

    async def register(
        self,
        session_id: str,
        hostname: str,
        gateway_id: str,
        ttl: int = _SESSION_TTL,
    ) -> None:
        """Record that session_id is held by this gateway instance."""
        key = f"session:{session_id}"
        # Pipeline hset + expire so the hash never lands without a TTL — a drop
        # between two separate round-trips would otherwise leak the session key.
        pipe = self._r.pipeline()
        pipe.hset(key, mapping={"hostname": hostname, "gateway_id": gateway_id})
        pipe.expire(key, ttl)
        await pipe.execute()
        logger.debug(f"Session registered: session_id={session_id} gateway={gateway_id}")

    async def get(self, session_id: str) -> dict | None:
        h = await self._r.hgetall(f"session:{session_id}")
        return h or None

    async def refresh(self, session_id: str, ttl: int = _SESSION_TTL) -> None:
        await self._r.expire(f"session:{session_id}", ttl)

    async def delete(self, session_id: str) -> None:
        await self._r.delete(f"session:{session_id}")
        logger.debug(f"Session deleted: session_id={session_id}")

    async def subscribe(self, session_id: str) -> AsyncGenerator[dict, None]:
        """Yield JSON-RPC response dicts published to this session's channel.

        Uses a dedicated pub/sub connection so the main Redis client is free
        for command traffic.  Exits when the generator is cancelled (client
        disconnect).
        """
        channel = f"session:{session_id}:results"
        throttle = _RefreshThrottle(_REFRESH_THROTTLE)
        async with self._ps.pubsub() as ps:
            await ps.subscribe(channel)
            logger.debug(f"Subscribed to {channel}")
            try:
                async for msg in ps.listen():
                    if msg["type"] == "message":
                        # Throttle TTL refreshes so a busy stream doesn't issue
                        # one EXPIRE per message (RC-3).
                        if throttle.ready(time.monotonic()):
                            await self.refresh(session_id)
                        try:
                            yield json.loads(msg["data"])
                        except json.JSONDecodeError:
                            logger.warning(f"Non-JSON message on {channel}: {msg['data']!r}")
            finally:
                logger.debug(f"Unsubscribed from {channel}")

    async def publish_result(self, session_id: str, result: dict) -> None:
        """Publish a JSON-RPC result to the session's pub/sub channel."""
        channel = f"session:{session_id}:results"
        await self._r.publish(channel, json.dumps(result))
