# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Device Pod - isolated MCP server instance per API/device.

Each pod runs its own MCP event loop serving tools, resources, and prompts.
Pods are spawned/teared by the Registry based on device health and spec availability.
"""

import asyncio
import json
import ssl
from typing import Any
from urllib.parse import quote

import httpx
import jsonschema
from loguru import logger
from mcp.server.fastmcp import FastMCP
from pybreaker import CircuitBreaker, CircuitBreakerError

from device_mcp_gateway import metrics
from device_mcp_gateway.audit import redact_url
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.core.adapter import (
    ERR_CIRCUIT_OPEN,
    ERR_CONNECTION,
    ERR_INTERNAL,
    ERR_TIMEOUT,
    DeviceAdapter,
)
from device_mcp_gateway.core.backoff import RetryPolicy, send_with_retry
from device_mcp_gateway.core.errors import (
    RPC_INTERNAL_ERROR,
    RPC_INVALID_PARAMS,
    RPC_METHOD_NOT_FOUND,
    rpc_error,
)
from device_mcp_gateway.pods.sse_server import SseTransport
from device_mcp_gateway.pods.rate_limiter import TokenBucket
from device_mcp_gateway.core.translator import McpManifest, McpTool

# MCP protocol versions this gateway speaks, newest first. The `initialize`
# handshake echoes the client's requested version when we support it, otherwise
# it falls back to our preferred (newest) version per the MCP spec. Keeping this
# as data — rather than a hardcoded literal in the handler — means version
# support is one edit, and negotiation is testable in isolation (F-15).
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-06-18", "2025-03-26", "2024-11-05")
PREFERRED_PROTOCOL_VERSION: str = SUPPORTED_PROTOCOL_VERSIONS[0]


def negotiate_protocol_version(requested: Any) -> str:
    """Resolve the MCP protocolVersion to advertise in the initialize response.

    Echoes the client's requested version when supported; otherwise returns our
    preferred (newest) version, signalling the client to retry on that version.
    A missing/invalid request also yields the preferred version.
    """
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return PREFERRED_PROTOCOL_VERSION


# Headers a tool argument must never be able to set on the upstream request (Tier-0 F-25).
# Without this, an `in: header` parameter could overwrite the device's auth header or
# smuggle routing/cache headers, since untrusted header params were merged over auth.
_RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "host",
        "content-length",
        "content-type",
        "connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "via",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    }
)

# Cap the upstream response body the pod will buffer/return to the LLM (Tier-0 F-27).
# An unbounded body is both a memory-DoS vector and an oversized prompt-injection channel.
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MiB


def _sanitize_header_params(items: dict[str, Any]) -> dict[str, str]:
    """Drop reserved headers and reject CRLF in values (Tier-0 F-25)."""
    safe: dict[str, str] = {}
    for k, v in items.items():
        if k.lower() in _RESERVED_HEADERS:
            logger.warning(f"Dropping reserved header param '{k}' from tool call")
            continue
        sv = str(v)
        if "\r" in sv or "\n" in sv:
            logger.warning(f"Dropping header param '{k}' with CRLF in its value")
            continue
        safe[k] = sv
    return safe


def _validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> str | None:
    """Validate tool-call arguments against the tool's JSON schema (Tier-0 F-28).

    Returns an error string if the arguments violate the schema, else None. If the
    schema itself is not a valid JSON Schema (some flattened specs aren't), validation
    is skipped (logged) rather than blocking a legitimate call.
    """
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.exceptions.SchemaError:
        logger.warning("Tool input schema is not valid JSON Schema; skipping argument validation")
        return None
    try:
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
    except Exception:
        logger.warning("Argument validation raised on this schema; skipping (fail-open)")
        return None
    if errors:
        e = errors[0]
        loc = "/".join(str(p) for p in e.path) or "(root)"
        return f"{loc}: {e.message}"
    return None


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
        request_timeout: float = 15,
        retry_policy: RetryPolicy | None = None,
        tls_verify: "ssl.SSLContext | bool" = True,
    ):
        self.hostname = hostname
        self.manifest = manifest
        self.transport = transport
        self.auth = auth
        self.base_url = base_url
        self._keep_alive_interval = keep_alive_interval
        self._request_timeout = request_timeout
        # Outbound TLS for tool calls to this device (F-31). True = httpx default
        # certifi server verification; an SSLContext carries a client cert and/or
        # a private CA for mutual TLS.
        self._tls_verify = tls_verify
        # Bounded jittered retries for idempotent tool calls (F-05/F-44).
        self._retry_policy = retry_policy or RetryPolicy()
        # One reused HTTP client per pod (created lazily) instead of one per
        # tool call — keeps connections/TLS alive across invocations (F8).
        self._http: httpx.AsyncClient | None = None
        self._rate_limiter = TokenBucket(rate_limit_rps) if rate_limit_rps and rate_limit_rps > 0 else None
        # Open after 5 consecutive 5xx/connection failures; reset after 60s.
        # 4xx responses do not trip the breaker (client error, not device failure).
        self._breaker = CircuitBreaker(fail_max=5, reset_timeout=60)
        self._mcp = FastMCP(
            name=f"mcp-{hostname}",
            instructions=f"{manifest.server_name} v{manifest.server_version}",
        )
        self._running = False
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self.sse_transport: SseTransport | None = None
        # Per-device request-encoder + response-normalizer seam (F-49 / F-39 / F-40).
        self._adapter = DeviceAdapter(max_response_bytes=_MAX_RESPONSE_BYTES)
        self._register_tools()

    def breaker_snapshot(self) -> dict:
        """Current circuit-breaker state for diagnostics (F-52).

        ``state`` is ``closed`` (healthy), ``open`` (shedding after too many recent
        failures), or ``half-open`` (probing recovery). ``fail_counter`` is the
        consecutive-failure count toward ``fail_max``.
        """
        return {
            "state": self._breaker.current_state,
            "fail_counter": self._breaker.fail_counter,
            "fail_max": self._breaker.fail_max,
            "reset_timeout": self._breaker.reset_timeout,
        }

    def _client(self) -> httpx.AsyncClient:
        """Return the pod's shared HTTP client, creating it on first use."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=self._request_timeout, follow_redirects=True, verify=self._tls_verify
            )
        return self._http

    async def aclose(self) -> None:
        """Close the shared HTTP client. Called when the pod is torn down."""
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()

    def _register_tools(self) -> None:
        """Register all MCP tools from the manifest as async callables."""
        self._tool_dispatch: dict[str, Any] = {}
        # name → JSON input schema, for server-side argument validation (Tier-0 F-28).
        self._tool_schemas: dict[str, dict[str, Any]] = {t.name: t.schema for t in self.manifest.tools}
        _get_client = self._client  # shared client for all tool closures
        # Capture once so all tool closures share the same per-pod circuit breaker
        # without it appearing in the function signature (Pydantic would warn on it).
        _pod_breaker = self._breaker
        _adapter = self._adapter  # request encoder + response normalizer (F-49)
        _retry_policy = self._retry_policy  # bounded jittered retries (F-05/F-44)
        _hostname = self.hostname

        def _count_retry(_attempt: int, reason: str) -> None:
            metrics.upstream_retries_total.labels(hostname=_hostname, reason=reason).inc()

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

                # Split kwargs by declared parameter location. Collision-renamed args map
                # back to their upstream wire name for query/header (F-04); body fields are
                # mapped inside the adapter, and path params are never renamed.
                def _wire(name: str) -> str:
                    return tool.param_wire_names.get(name, name)

                path_params = {k: v for k, v in kwargs.items() if tool.param_locations.get(k) == "path"}
                body_params = {k: v for k, v in kwargs.items() if tool.param_locations.get(k) == "body"}
                query_params = {_wire(k): v for k, v in kwargs.items() if tool.param_locations.get(k) == "query"}
                header_params = {_wire(k): v for k, v in kwargs.items() if tool.param_locations.get(k) == "header"}
                # Params with no declared location fall back to method-appropriate defaults
                unlocated = {k: v for k, v in kwargs.items() if k not in tool.param_locations}
                if tool.method in ("POST", "PUT", "PATCH"):
                    body_params.update(unlocated)
                else:
                    query_params.update(unlocated)

                # URL-encode each path param so a value like '../admin' or 'a/b' can't traverse
                # or inject extra path segments (Tier-1 F-04). Format only the path template —
                # base_url is concatenated raw so a literal '{' in it isn't mis-parsed.
                encoded_path = {k: quote(str(v), safe="") for k, v in path_params.items()}
                try:
                    url = base_url + tool.path.format_map(encoded_path)
                except (KeyError, IndexError, ValueError) as exc:
                    return _adapter.error_envelope(
                        ERR_INTERNAL, f"Path template error for {tool.path}: missing/invalid {exc}", status=500
                    )
                # Start from sanitized, untrusted header params, then apply auth LAST so a
                # tool argument can never override the device's credentials (Tier-0 F-25).
                # Auth may live in a header, query param, or cookie (F-43).
                headers = _sanitize_header_params(header_params)
                auth_material = await auth.apply() if auth else None
                # Encode the body per the operation's declared content type (F-40): JSON,
                # form, multipart, or raw — instead of always sending json=.
                body_kwargs = _adapter.encode_body(tool, body_params)
                # A raw body carries its own content-type header; merge it under auth.
                body_headers = body_kwargs.pop("headers", None)
                if body_headers:
                    headers = {**body_headers, **headers}
                cookies = None
                if auth_material:
                    headers.update(auth_material.headers)
                    if auth_material.params:
                        query_params = {**query_params, **auth_material.params}
                    cookies = auth_material.cookies or None

                async def _send():
                    return await _get_client().request(
                        method=tool.method,
                        url=url,
                        headers=headers,
                        params=query_params or None,
                        cookies=cookies,
                        **body_kwargs,
                    )

                async def _call():
                    # Bounded jittered retries on transient failures — idempotent (GET)
                    # methods only; honors 429 Retry-After (F-05/F-44). Runs inside the
                    # breaker so one logical call = one breaker outcome.
                    resp = await send_with_retry(
                        _send,
                        method=tool.method,
                        policy=_retry_policy,
                        on_retry=_count_retry,
                    )
                    # Only raise on 5xx — device-side failures trip the breaker.
                    # 4xx are client/LLM errors and should not affect circuit state.
                    if 500 <= resp.status_code < 600:
                        resp.raise_for_status()
                    return resp

                try:
                    # calling() is a sync context manager that tracks state for asyncio
                    # (call_async requires Tornado and is not usable in asyncio contexts).
                    with _pod_breaker.calling():
                        resp = await _call()
                    # Normalize into the uniform result envelope (F-39): 4xx becomes an
                    # error rather than a fake success; the body cap (F-27) lives here too.
                    return _adapter.build_result(resp)
                except CircuitBreakerError:
                    logger.warning(f"Circuit breaker open for pod {redact_url(base_url)}")
                    metrics.circuit_breaker_opens_total.labels(hostname=self.hostname).inc()
                    return _adapter.error_envelope(
                        ERR_CIRCUIT_OPEN,
                        "Device unavailable: circuit breaker open (too many recent failures)",
                        status=503,
                    )
                except httpx.HTTPStatusError as e:
                    # 5xx (raised above so it trips the breaker) → normalized error envelope.
                    return _adapter.normalize_http_error(e.response)
                except httpx.TimeoutException as e:
                    return _adapter.error_envelope(ERR_TIMEOUT, f"Device request timed out: {e}", status=504)
                except httpx.RequestError as e:
                    return _adapter.error_envelope(ERR_CONNECTION, f"Device request failed: {e}", status=502)
                except Exception as e:
                    return _adapter.error_envelope(ERR_INTERNAL, str(e))

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
                    "protocolVersion": negotiate_protocol_version(params.get("protocolVersion")),
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
                {"name": t.name, "description": t.description, "inputSchema": t.schema} for t in self.manifest.tools
            ]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}

        if method == "tools/call":
            tool_name: str = params.get("name") or ""
            arguments = params.get("arguments") or {}
            handler = self._tool_dispatch.get(tool_name)
            if not handler:
                return rpc_error(RPC_METHOD_NOT_FOUND, msg_id, message=f"Tool not found: {tool_name}")
            # Validate arguments against the tool's declared JSON schema before dispatch
            # (Tier-0 F-28) so malformed/over-posted params don't reach the upstream.
            if not isinstance(arguments, dict):
                return rpc_error(RPC_INVALID_PARAMS, msg_id, message="Invalid params: 'arguments' must be an object")
            schema = self._tool_schemas.get(tool_name)
            if schema is not None:
                arg_error = _validate_arguments(schema, arguments)
                if arg_error:
                    return rpc_error(RPC_INVALID_PARAMS, msg_id, message=f"Invalid params: {arg_error}")
            try:
                result = await handler(**arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                }
            except Exception as e:
                logger.error(f"Tool call failed for {tool_name}: {e}")
                return rpc_error(RPC_INTERNAL_ERROR, msg_id, message=str(e))

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
                return rpc_error(RPC_INVALID_PARAMS, msg_id, message=f"Unknown resource URI: {uri}")
            path = uri[len(prefix) :]
            # Reject path traversal / off-API escapes (Tier-0 F-29): the path is appended to
            # base_url, so '..' or a scheme/host-relative path could read off the intended API.
            if path and (".." in path or not path.startswith("/")):
                return rpc_error(RPC_INVALID_PARAMS, msg_id, message=f"Invalid resource path in URI: {uri}")
            if self._rate_limiter:
                await self._rate_limiter.acquire()
            auth_material = await self.auth.apply() if self.auth else None
            headers = auth_material.headers if auth_material else {}
            try:
                resp = await self._client().get(
                    f"{self.base_url}{path}",
                    headers=headers,
                    params=(auth_material.params or None) if auth_material else None,
                    cookies=(auth_material.cookies or None) if auth_material else None,
                )
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
                return rpc_error(RPC_INTERNAL_ERROR, msg_id, message=str(e))

        # Unknown method — only send an error if this was a request (has an id)
        if msg_id is not None:
            return rpc_error(RPC_METHOD_NOT_FOUND, msg_id, message=f"Method not found: {method}")
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
