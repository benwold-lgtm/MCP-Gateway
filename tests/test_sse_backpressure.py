# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for embedded-mode SSE backpressure visibility (SRE #10).

A full client queue used to drop the JSON-RPC response silently, leaving the
client to hang. send_to_client now reports non-delivery and handle_message
surfaces it to the POST caller as an error.
"""

import asyncio

import pytest

from device_mcp_gateway.pods.sse_server import SseTransport


async def _handler_ok(message):
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}


def _fill_queue(q):
    while True:
        try:
            q.put_nowait({"event": "message", "data": "x"})
        except asyncio.QueueFull:
            break


@pytest.mark.asyncio
async def test_send_to_client_false_for_unknown_session():
    t = SseTransport("h", _handler_ok)
    assert await t.send_to_client("nope", {"x": 1}) is False


@pytest.mark.asyncio
async def test_send_to_client_true_on_delivery():
    t = SseTransport("h", _handler_ok)
    t.register_client("s1", "/endpoint")
    assert await t.send_to_client("s1", {"x": 1}) is True


@pytest.mark.asyncio
async def test_send_to_client_false_when_queue_full():
    t = SseTransport("h", _handler_ok)
    q = t.register_client("s1", "/endpoint")
    _fill_queue(q)
    assert await t.send_to_client("s1", {"x": 1}) is False


@pytest.mark.asyncio
async def test_handle_message_surfaces_backpressure_error():
    t = SseTransport("h", _handler_ok)
    q = t.register_client("s1", "/endpoint")
    _fill_queue(q)
    resp = await t.handle_message("s1", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp.get("status_code") == 503
    assert "backpressure" in resp["error"].lower()


@pytest.mark.asyncio
async def test_handle_message_accepted_when_deliverable():
    t = SseTransport("h", _handler_ok)
    t.register_client("s1", "/endpoint")
    resp = await t.handle_message("s1", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp == {"status": "accepted"}
