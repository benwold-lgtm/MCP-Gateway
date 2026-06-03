"""
SSE Transport Adapter for MCP.
Exposes MCP messages via Server-Sent Events endpoint.
"""

import asyncio
import json
from collections import defaultdict
from typing import Any, AsyncGenerator

from loguru import logger


class SseTransport:
    """
    SSE-based MCP transport.
    Provides:
      - /sse endpoint for streaming messages
      - /messages POST endpoint for client-to-server communication
    """

    def __init__(self, hostname: str, message_handler):
        """
        Args:
            hostname: Unique device hostname for namespacing this transport
            message_handler: Async callable that processes MCP JSON-RPC messages
        """
        self.hostname = hostname
        self._handler = message_handler
        self._clients: dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
        self._running = False

    def register_client(self, client_id: str) -> asyncio.Queue:
        """Register a new SSE client and return their message queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._clients[client_id] = q
        logger.info(f"SSE client {client_id} registered for {self.hostname}")
        # Send an immediate connection acknowledgement so streaming clients
        # can establish the event stream without waiting for the first tool
        # message.
        try:
            q.put_nowait({"event": "connected", "data": ""})
        except asyncio.QueueFull:
            logger.warning(f"Failed to enqueue connected event for {client_id}")
        return q

    async def send_to_client(self, client_id: str, message: Any) -> None:
        """Send a JSON-RPC message to a specific client queue."""
        q = self._clients.get(client_id)
        if q:
            if isinstance(message, dict):
                message = {"event": "message", "data": json.dumps(message)}
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                logger.warning(f"SSE queue full for client {client_id}, dropping message")

    async def event_stream(self, client_id: str) -> AsyncGenerator[Any, None]:
        """Yield SSE events from the client's queue.

        The try/finally guarantees the client entry is removed from _clients
        whether the connection ends normally, the client disconnects (GeneratorExit
        thrown by EventSourceResponse.aclose()), or the task is cancelled.
        """
        q = self._clients.get(client_id)
        if not q:
            return
        try:
            while self._running:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield msg
                except asyncio.TimeoutError:
                    yield {"event": "keep-alive", "data": ""}
        finally:
            self._clients.pop(client_id, None)
            logger.info(f"SSE client {client_id} disconnected from {self.hostname}")

    async def handle_message(self, client_id: str, params: dict) -> dict | None:
        """Pass incoming MCP request to the handler, return response if needed."""
        try:
            result = await self._handler(params)
            await self.send_to_client(client_id, result)
            return {"status": "sent"}
        except Exception as e:
            logger.error(f"SSE message handling error: {e}")
            return {"error": str(e)}

    async def start(self) -> None:
        self._running = True
        logger.info(f"SSE transport started for {self.hostname}")

    async def stop(self) -> None:
        self._running = False
        for q in self._clients.values():
            q.put_nowait({"event": "shutdown", "data": "Server shutdown"})
        self._clients.clear()
        logger.info(f"SSE transport stopped for {self.hostname}")
