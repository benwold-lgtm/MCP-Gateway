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
from typing import Any, AsyncGenerator

from loguru import logger

_SESSION_TTL = 86_400  # 24 h — refreshed on every message


class SessionRouter:
    """Register SSE sessions and route results across gateway instances."""

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client

    async def register(
        self,
        session_id: str,
        hostname: str,
        gateway_id: str,
        ttl: int = _SESSION_TTL,
    ) -> None:
        """Record that session_id is held by this gateway instance."""
        key = f"session:{session_id}"
        await self._r.hset(key, mapping={"hostname": hostname, "gateway_id": gateway_id})
        await self._r.expire(key, ttl)
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
        async with self._r.pubsub() as ps:
            await ps.subscribe(channel)
            logger.debug(f"Subscribed to {channel}")
            try:
                async for msg in ps.listen():
                    if msg["type"] == "message":
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
