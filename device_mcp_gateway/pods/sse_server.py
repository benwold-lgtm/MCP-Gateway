# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
SSE Transport Adapter for MCP.

Implements the MCP SSE transport protocol (https://spec.modelcontextprotocol.io):
  - GET /sse   — client opens SSE stream; server immediately sends an 'endpoint' event
                 whose data is the POST URL for this session.
  - POST /messages — client sends JSON-RPC 2.0 requests; server replies via SSE
                     'message' events on the open stream.
"""

import asyncio
import json
from typing import Any, AsyncGenerator

from loguru import logger

from device_mcp_gateway import metrics

_SENTINEL = object()


class SseTransport:
    """SSE-based MCP transport for a single device pod."""

    def __init__(self, hostname: str, message_handler, keep_alive_interval: int = 30):
        """
        Args:
            hostname: Device hostname, used for log scoping.
            message_handler: Async callable (message: dict) -> dict | None
                             Returns a JSON-RPC 2.0 response dict, or None for notifications.
            keep_alive_interval: Seconds between keep-alive pings when the queue is idle.
        """
        self.hostname = hostname
        self._handler = message_handler
        self._clients: dict[str, asyncio.Queue] = {}
        self._running = False
        self._keep_alive_interval = keep_alive_interval

    def register_client(self, session_id: str, endpoint_url: str) -> asyncio.Queue:
        """Register a new SSE client and enqueue the MCP 'endpoint' event.

        The 'endpoint' event is required by the MCP SSE transport spec: it tells the
        client which URL to POST JSON-RPC messages to for this session.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._clients[session_id] = q
        logger.info(f"SSE client {session_id} registered for {self.hostname}")
        try:
            q.put_nowait({"event": "endpoint", "data": endpoint_url})
        except asyncio.QueueFull:
            logger.warning(f"Failed to enqueue endpoint event for {session_id}")
        return q

    async def send_to_client(self, session_id: str, message: Any) -> bool:
        """Enqueue a JSON-RPC message for delivery to a specific client.

        Returns True if the message was enqueued, False if it could not be
        delivered (unknown session, or the client's queue is full because it has
        stopped consuming). The caller surfaces a False as an error rather than
        letting the response vanish silently (SRE #10).
        """
        q = self._clients.get(session_id)
        if q is None:
            return False
        if isinstance(message, dict):
            message = {"event": "message", "data": json.dumps(message)}
        try:
            q.put_nowait(message)
            return True
        except asyncio.QueueFull:
            logger.warning(f"SSE queue full for client {session_id}; backpressure, message not delivered")
            metrics.sse_messages_dropped_total.labels(hostname=self.hostname).inc()
            return False

    async def event_stream(self, session_id: str) -> AsyncGenerator[Any, None]:
        """Yield SSE events from the client's queue.

        Exits immediately when stop() is called (via sentinel value) rather than
        waiting up to keep_alive_interval seconds for the timeout to fire.
        """
        q = self._clients.get(session_id)
        if not q:
            return
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=self._keep_alive_interval)
                    if msg is _SENTINEL:
                        break
                    yield msg
                except asyncio.TimeoutError:
                    yield {"event": "keep-alive", "data": ""}
        finally:
            self._clients.pop(session_id, None)
            logger.info(f"SSE client {session_id} disconnected from {self.hostname}")

    async def handle_message(self, session_id: str, message: dict) -> dict:
        """Process an incoming JSON-RPC 2.0 message and push the response via SSE.

        Notifications (no 'id' field, or method starting with 'notifications/') produce
        no SSE response; for those the handler returns None.
        """
        try:
            result = await self._handler(message)
            if result is not None:
                delivered = await self.send_to_client(session_id, result)
                if not delivered:
                    # The response could not be queued to the client's stream
                    # (gone or not consuming). Tell the POST caller instead of
                    # dropping the JSON-RPC response silently (SRE #10).
                    return {
                        "error": "SSE stream backpressure: response could not be delivered",
                        "status_code": 503,
                    }
            return {"status": "accepted"}
        except Exception as e:
            logger.error(f"SSE message handling error: {e}")
            return {"error": str(e)}

    async def start(self) -> None:
        self._running = True
        logger.info(f"SSE transport started for {self.hostname}")

    async def stop(self) -> None:
        """Stop the transport, unblocking all open event_stream generators immediately.

        Drains each client queue before pushing the sentinel so the sentinel always
        fits regardless of queue fullness (maxsize=1000).
        """
        self._running = False
        for q in list(self._clients.values()):
            while not q.empty():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    break
            q.put_nowait(_SENTINEL)  # queue is now empty; cannot raise QueueFull
        self._clients.clear()
        logger.info(f"SSE transport stopped for {self.hostname}")
