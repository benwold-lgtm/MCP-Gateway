import asyncio
from unittest.mock import MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from device_mcp_gateway.core.translator import McpManifest, McpTool
from device_mcp_gateway.pods.device_pod import DevicePod
from device_mcp_gateway.pods.transport.sse_server import SseTransport


@pytest.fixture
def simple_manifest() -> McpManifest:
    return McpManifest(
        server_name="mcp-test",
        server_version="1.0.0",
        hostname="test-device",
        tools=[
            McpTool(
                name="ping",
                description="Ping test",
                schema={"type": "object", "properties": {}},
                method="GET",
                path="/ping",
            )
        ],
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "transport,patch_target,method_name",
    [
        ("sse", SseTransport, "start"),
        ("stdio", FastMCP, "run_stdio_async"),
        ("http", FastMCP, "run_streamable_http_async"),
    ],
)
async def test_device_pod_start_and_stop(monkeypatch, simple_manifest, transport, patch_target, method_name):
    started = {
        "count": 0,
    }

    async def fake_run(self, mount_path=None):
        started["count"] += 1
        try:
            while True:
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            raise

    monkeypatch.setattr(patch_target, method_name, fake_run)

    pod = DevicePod(
        hostname="test-device",
        manifest=simple_manifest,
        transport=transport,
        base_url="http://localhost:1234",
    )

    await pod.start()
    assert pod._running is True
    assert pod._task is not None
    await asyncio.sleep(0)
    assert started["count"] == 1

    pod.stop()
    await asyncio.sleep(0)
    assert pod._running is False
    assert pod._task.done() is True
    assert pod._task.cancelled() is True


@pytest.mark.anyio
async def test_device_pod_unsupported_transport(simple_manifest):
    pod = DevicePod(
        hostname="test-device",
        manifest=simple_manifest,
        transport="unsupported",
        base_url="http://localhost:1234",
    )

    with pytest.raises(ValueError, match="Unsupported transport"):
        await pod.start()


@pytest.mark.anyio
async def test_path_param_substituted_in_url():
    """Path parameters must be interpolated into the URL, not sent as query params."""
    manifest = McpManifest(
        server_name="mcp-test",
        server_version="1.0.0",
        hostname="test-device",
        tools=[
            McpTool(
                name="get_item",
                description="Get item by ID",
                schema={"type": "object", "properties": {"item_id": {"type": "integer"}}, "required": ["item_id"]},
                method="GET",
                path="/items/{item_id}",
                param_locations={"item_id": "path"},
            )
        ],
    )

    captured: dict = {}

    async def fake_request(self, method, url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"id": 42}
        resp.raise_for_status = MagicMock()
        return resp

    with patch("httpx.AsyncClient.request", fake_request):
        pod = DevicePod(
            hostname="test-device",
            manifest=manifest,
            transport="sse",
            base_url="http://device.local",
        )
        # Directly invoke the registered tool's underlying callable
        tool_fn = pod._mcp._tool_manager._tools["get_item"].fn
        await tool_fn(item_id=42)

    assert captured["url"] == "http://device.local/items/42", f"Unexpected URL: {captured['url']}"
    assert not captured.get("params"), "Path param should not appear as query param"


@pytest.mark.anyio
async def test_query_params_not_in_path():
    """Query parameters must be sent as ?key=val, not interpolated into the URL."""
    manifest = McpManifest(
        server_name="mcp-test",
        server_version="1.0.0",
        hostname="test-device",
        tools=[
            McpTool(
                name="list_items",
                description="List items",
                schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
                method="GET",
                path="/items",
                param_locations={"limit": "query"},
            )
        ],
    )

    captured: dict = {}

    async def fake_request(self, method, url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = []
        resp.raise_for_status = MagicMock()
        return resp

    with patch("httpx.AsyncClient.request", fake_request):
        pod = DevicePod(
            hostname="test-device",
            manifest=manifest,
            transport="sse",
            base_url="http://device.local",
        )
        tool_fn = pod._mcp._tool_manager._tools["list_items"].fn
        await tool_fn(limit=10)

    assert captured["url"] == "http://device.local/items"
    assert captured["params"] == {"limit": 10}
