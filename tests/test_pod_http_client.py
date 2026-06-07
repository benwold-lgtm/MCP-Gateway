# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for the per-pod reused HTTP client (S2 finding F8).

DevicePod previously opened and closed a fresh httpx.AsyncClient on every tool
call (new connection/TLS each time). It now keeps one client per pod, reused
across calls and closed when the pod is torn down.
"""

import pytest

from device_mcp_gateway.core.translator import McpManifest, McpTool
from device_mcp_gateway.pods.device_pod import DevicePod


def _pod() -> DevicePod:
    manifest = McpManifest(
        server_name="mcp-test",
        server_version="1.0.0",
        hostname="dev1",
        tools=[McpTool(name="ping", description="", schema={}, method="GET", path="/ping")],
    )
    return DevicePod(hostname="dev1", manifest=manifest, base_url="http://dev1")


def test_client_is_reused_across_calls():
    pod = _pod()
    c1 = pod._client()
    c2 = pod._client()
    assert c1 is c2  # one client reused, not recreated per call


@pytest.mark.asyncio
async def test_aclose_closes_client_and_recreates_on_demand():
    pod = _pod()
    c1 = pod._client()
    assert c1.is_closed is False

    await pod.aclose()
    assert c1.is_closed is True

    # A subsequent use lazily creates a fresh client.
    c2 = pod._client()
    assert c2 is not c1
    assert c2.is_closed is False
    await pod.aclose()


@pytest.mark.asyncio
async def test_aclose_is_safe_when_never_used():
    pod = _pod()  # client never created
    await pod.aclose()  # must not raise
