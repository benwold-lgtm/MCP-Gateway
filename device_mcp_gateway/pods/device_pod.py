"""
Device Pod - isolated MCP server instance per API/device.

Each pod runs its own MCP event loop serving tools, resources, and prompts.
Pods are spawned/teared by the Registry based on device health and spec availability.
"""

import asyncio
import base64
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
    """Manages a single per-hostname MCP server process."""

    def __init__(
        self,
        hostname: str,
        manifest: McpManifest,
        transport: str = "sse",
        auth: AbstractAuth | None = None,
        base_url: str = "",
        rate_limit_rps: float | None = None,
    ):
        self.hostname = hostname
        self.manifest = manifest
        self.transport = transport
        self.auth = auth
        self.base_url = base_url
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
                query_params = {k: v for k, v in kwargs.items() if tool.param_locations.get(k) in ("query", "header")}
                # Params with no declared location fall back to method-appropriate defaults
                unlocated = {k: v for k, v in kwargs.items() if k not in tool.param_locations}
                if tool.method in ("POST", "PUT", "PATCH"):
                    body_params.update(unlocated)
                else:
                    query_params.update(unlocated)

                url = f"{base_url}{tool.path}".format_map(path_params)
                headers = await auth.get_headers() if auth else {}
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
            self.sse_transport = SseTransport(self.hostname, self._handle_sse_message)
        return self.sse_transport

    async def _handle_sse_message(self, params: dict) -> dict[str, Any]:
        tool_name = params.get("tool")
        arguments = params.get("arguments", {})
        if not tool_name:
            return {"error": "tool is required"}

        handler = self._tool_dispatch.get(tool_name)
        if not handler:
            available = list(self._tool_dispatch.keys())
            logger.error(f"Unknown tool: {tool_name}; available: {available}")
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            result = await handler(**arguments)
            return {"result": result}
        except Exception as e:
            logger.error(f"SSE tool call failed for {tool_name}: {e}")
            return {"error": str(e)}

    async def start(self) -> None:
        """Start the MCP server."""
        if self._running:
            return
        if self.transport != "sse":
            raise ValueError(f"Unsupported transport: {self.transport}")
        self._running = True
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run_sse())
        logger.info(f"Pod started for {self.hostname} via {self.transport}")

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
