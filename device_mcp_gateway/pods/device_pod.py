"""
Device Pod - isolated MCP server instance per API/device.

Each pod runs its own MCP event loop serving tools, resources, and prompts.
Pods are spawned/teared by the Registry based on device health and spec availability.
"""

import asyncio
import base64
import json
import time
from typing import Any

import httpx
from loguru import logger
from mcp.server.fastmcp import FastMCP

from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.pods.transport import SseTransport
from device_mcp_gateway.core.translator import McpManifest, McpTool


class _TokenBucket:
    """Asyncio token bucket for per-device downstream rate limiting."""

    def __init__(self, rate: float) -> None:
        self._rate = rate  # tokens per second (= max RPS)
        self._tokens = float(rate)
        self._last = time.monotonic()

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def tokens(self) -> float:
        now = time.monotonic()
        refilled = min(self._rate, self._tokens + (now - self._last) * self._rate)
        return round(refilled, 3)

    async def acquire(self) -> None:
        while True:
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            await asyncio.sleep((1.0 - self._tokens) / self._rate)


class DevicePod:
    """Manages a single per-hostname MCP server instance.

    In embedded mode the pod also owns an SseTransport.
    In distributed mode the worker calls call_tool() directly and results
    are routed through Redis pub/sub — no SseTransport is created.
    """

    def __init__(
        self,
        hostname: str,
        manifest: McpManifest,
        transport: str = "sse",
        auth: AbstractAuth | None = None,
        base_url: str = "",
        rate_limit_rps: float | None = None,
        keep_alive_interval: int = 30,
    ):
        self.hostname = hostname
        self.manifest = manifest
        self.transport = transport
        self.auth = auth
        self.base_url = base_url
        self._keep_alive_interval = keep_alive_interval
        self._rate_limiter = _TokenBucket(rate_limit_rps) if rate_limit_rps and rate_limit_rps > 0 else None
        self._mcp = FastMCP(
            name=f"mcp-{hostname}",
            instructions=f"{manifest.server_name} v{manifest.server_version}",
        )
        self._running = False
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self.sse_transport: SseTransport | None = None
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all MCP tools from the manifest as async callables."""
        self._tool_dispatch: dict[str, Any] = {}
        for tool in self.manifest.tools:
            # Build a callable closure per tool. All closure variables are bound
            # via default-argument so each iteration captures its own snapshot.
            async def call_api(
                tool: McpTool = tool,
                auth=self.auth,
                base_url: str = self.base_url,
                rate_limiter=self._rate_limiter,
                **kwargs: Any,
            ) -> Any:
                if rate_limiter:
                    await rate_limiter.acquire()

                # Split kwargs by declared parameter location
                path_params = {k: v for k, v in kwargs.items() if tool.param_locations.get(k) == "path"}
                body_params = {k: v for k, v in kwargs.items() if tool.param_locations.get(k) == "body"}
                query_params = {k: v for k, v in kwargs.items() if tool.param_locations.get(k) == "query"}
                extra_headers = {k: str(v) for k, v in kwargs.items() if tool.param_locations.get(k) == "header"}
                # Params with no declared location fall back to method-appropriate defaults
                unlocated = {k: v for k, v in kwargs.items() if k not in tool.param_locations}
                if tool.method in ("POST", "PUT", "PATCH"):
                    body_params.update(unlocated)
                else:
                    query_params.update(unlocated)

                url = f"{base_url}{tool.path}".format_map(path_params)
                headers = await auth.get_headers() if auth else {}
                headers.update(extra_headers)
                try:
                    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
                        resp = await c.request(
                            method=tool.method,
                            url=url,
                            headers=headers,
                            json=body_params if tool.method in ("POST", "PUT", "PATCH") else None,
                            params=query_params or None,
                        )
                    resp.raise_for_status()
                    if resp.status_code == 204 or not resp.content:
                        return {"status": resp.status_code, "body": None}
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct:
                        try:
                            return {"status": resp.status_code, "body": resp.json()}
                        except Exception:
                            pass
                    if ct.startswith("text/"):
                        return {"status": resp.status_code, "body": resp.text}
                    return {"status": resp.status_code, "body": base64.b64encode(resp.content).decode()}
                except httpx.HTTPStatusError as e:
                    return {"error": str(e), "status_code": e.response.status_code}
                except Exception as e:
                    return {"error": str(e)}

            # Store in local dispatch dict; FastMCP's **kwargs handling would
            # require a 'kwargs' key in arguments, so we bypass call_tool() and
            # invoke closures directly via _tool_dispatch.
            self._tool_dispatch[tool.name] = call_api
            self._mcp.tool(name=tool.name, description=tool.description)(call_api)
        logger.info(f"Registered {len(self.manifest.tools)} tools for pod {self.hostname}")

    def _ensure_sse_transport(self) -> SseTransport:
        if not self.sse_transport:
            self.sse_transport = SseTransport(
                self.hostname,
                self._handle_mcp_message,
                keep_alive_interval=self._keep_alive_interval,
            )
        return self.sse_transport

    async def _handle_mcp_message(self, message: dict) -> dict[str, Any] | None:
        """Handle an MCP JSON-RPC 2.0 message and return the response, or None for notifications."""
        msg_id = message.get("id")
        method = message.get("method", "")
        params = message.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"listChanged": False, "subscribe": False},
                    },
                    "serverInfo": {
                        "name": self.manifest.server_name,
                        "version": self.manifest.server_version,
                    },
                },
            }

        if method.startswith("notifications/"):
            return None  # notifications require no response

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            tools = [
                {"name": t.name, "description": t.description, "inputSchema": t.schema}
                for t in self.manifest.tools
            ]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}

        if method == "tools/call":
            tool_name: str = params.get("name") or ""
            arguments = params.get("arguments") or {}
            handler = self._tool_dispatch.get(tool_name)
            if not handler:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                }
            try:
                result = await handler(**arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                }
            except Exception as e:
                logger.error(f"Tool call failed for {tool_name}: {e}")
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": str(e)},
                }

        if method == "resources/list":
            resources = [
                {"uri": r.uri, "name": r.name, "description": r.description, "mimeType": r.mime_type}
                for r in self.manifest.resources
            ]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": resources}}

        if method == "resources/read":
            uri: str = params.get("uri") or ""
            prefix = f"device://{self.hostname}"
            if not uri.startswith(prefix):
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": f"Unknown resource URI: {uri}"},
                }
            path = uri[len(prefix):]
            if self._rate_limiter:
                await self._rate_limiter.acquire()
            headers = await self.auth.get_headers() if self.auth else {}
            try:
                async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
                    resp = await c.get(f"{self.base_url}{path}", headers=headers)
                resp.raise_for_status()
                ct = resp.headers.get("content-type", "")
                text = json.dumps(resp.json()) if "json" in ct else resp.text
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"contents": [{"uri": uri, "mimeType": ct or "application/json", "text": text}]},
                }
            except Exception as e:
                logger.error(f"Resource read failed for {uri}: {e}")
                return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": str(e)}}

        # Unknown method — only send an error if this was a request (has an id)
        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return None

    async def call_tool(self, message: dict) -> dict | None:
        """Public entry-point for the worker to dispatch an MCP JSON-RPC message.

        Returns the JSON-RPC response dict, or None for notifications.
        """
        return await self._handle_mcp_message(message)

    async def start(self, with_sse: bool = True) -> None:
        """Start the pod.

        Args:
            with_sse: If True (default, embedded mode), start the SSE transport
                      task so the pod accepts connections on its in-process queue.
                      Pass False in distributed mode — the worker calls call_tool()
                      directly and SSE routing goes through Redis.
        """
        if self._running:
            return
        if with_sse and self.transport != "sse":
            raise ValueError(f"Unsupported transport: {self.transport}")
        self._running = True
        self._stop_event = asyncio.Event()
        if with_sse:
            self._task = asyncio.create_task(self._run_sse())
        logger.info(f"Pod started for {self.hostname}")

    async def _run_sse(self) -> None:
        transport = self._ensure_sse_transport()
        await transport.start()
        try:
            await self._stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await transport.stop()

    def stop(self) -> None:
        """Gracefully stop the pod."""
        self._running = False
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info(f"Pod stopped for {self.hostname}")
