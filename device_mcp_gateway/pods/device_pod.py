"""
Device Pod - isolated MCP server instance per API/device.

Each pod runs its own MCP event loop serving tools, resources, and prompts.
Pods are spawned/teared by the Registry based on device health and spec availability.
"""

import asyncio
import base64
from typing import Any
import json

import httpx
from loguru import logger
from mcp.server.fastmcp import FastMCP

from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.pods.transport import SseTransport
from device_mcp_gateway.core.translator import McpManifest, McpTool


class DevicePod:
    """Manages a single per-hostname MCP server process."""

    def __init__(
        self,
        hostname: str,
        manifest: McpManifest,
        transport: str = "sse",
        auth: AbstractAuth | None = None,
        base_url: str = "",
    ):
        self.hostname = hostname
        self.manifest = manifest
        self.transport = transport
        self.auth = auth
        self.base_url = base_url
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
        for tool in self.manifest.tools:
            # Build a callable closure per tool
            async def call_api(
                tool: McpTool = tool,
                auth=None,
                base_url: str = self.base_url,
                **kwargs: Any,
            ) -> Any:
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

        try:
            result = await self._mcp.call_tool(tool_name, {"kwargs": arguments})

            # Normalize FastMCP ContentBlock results (e.g., TextContent) into
            # JSON-serializable structures. Many MCP tools return a sequence of
            # content blocks; prefer extracting text and parsing JSON when
            # possible so clients receive a predictable dict payload.
            try:
                if isinstance(result, list):
                    texts = []
                    for item in result:
                        text = getattr(item, "text", None)
                        if text is None:
                            texts.append(str(item))
                        else:
                            texts.append(text)
                    if len(texts) == 1:
                        try:
                            parsed = json.loads(texts[0])
                            # If the tool returned an envelope like {status: X, body: {...}},
                            # prefer returning the inner body to match client expectations.
                            if isinstance(parsed, dict) and "body" in parsed and "status" in parsed:
                                parsed = parsed["body"]
                            result = {"body": parsed}
                        except Exception:
                            result = {"body": texts[0]}
                    else:
                        result = {"body": texts}
            except Exception:
                # If normalization fails, fall back to the raw result
                pass

            return {"result": result}
        except Exception as e:
            available = list(self._mcp._tool_manager._tools.keys())
            logger.error(f"SSE tool call failed for {tool_name}: {e}; available tools: {available}")
            return {"error": str(e)}

    async def start(self) -> None:
        """Start the MCP server on the configured transport."""
        if self._running:
            return
        self._running = True
        self._stop_event = asyncio.Event()
        if self.transport == "sse":
            self._task = asyncio.create_task(self._run_sse())
        elif self.transport == "stdio":
            self._task = asyncio.create_task(self._run_stdio())
        elif self.transport == "http":
            self._task = asyncio.create_task(self._run_http())
        else:
            msg = f"Unsupported transport: {self.transport}"
            logger.error(msg)
            raise ValueError(msg)
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

    async def _run_stdio(self) -> None:
        await self._mcp.run_stdio_async()

    async def _run_http(self) -> None:
        await self._mcp.run_streamable_http_async()

    def stop(self) -> None:
        """Gracefully stop the pod."""
        self._running = False
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info(f"Pod stopped for {self.hostname}")
