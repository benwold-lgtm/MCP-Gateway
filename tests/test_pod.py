import asyncio

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
