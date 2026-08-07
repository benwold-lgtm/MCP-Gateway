# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Distributed result correlation for Streamable HTTP (Phase 6, Workstream A2).

The hard part of the transport. In embedded mode answering a POST is a function call. In
distributed mode the POST can land on **any** gateway replica, the device is owned by exactly
one worker, and the result is published to `session:{id}:results` in Redis — so the replica
handling the request has to wait for a result it does not produce and correlate it by
JSON-RPC id.

These run on the real-Redis tier, not fakeredis: the mechanism under test is stream ordering
and blocking `XREAD`, which is precisely what a test double would simulate rather than
exercise (TG-6, and the reason fakeredis cannot serve `get_device` here at all).

The worker is stood in for by a task that publishes results the way the real one does — but
the *gateway* side, which is the code under test, is the real implementation throughout.
"""

import asyncio

import pytest

from device_mcp_gateway.api.exchange import (
    DistributedResultExchange,
    ExchangeTimeout,
    ExchangeUnavailable,
)
from device_mcp_gateway.shared.keys import KEYS
from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
from device_mcp_gateway.shared.session_router import SessionRouter

pytestmark = pytest.mark.asyncio

SESSION = "sess-a2"
HOST = "dev-a2.local"


def _rpc_result(msg_id, payload=None):
    return {"jsonrpc": "2.0", "id": msg_id, "result": payload or {"content": []}}


async def _exchange(real_redis, *, backlog_limit=1000):
    backend = RedisRegistryBackend(real_redis)
    router = SessionRouter(real_redis, real_redis)
    await router.register(SESSION, HOST, "gw-test", owner="key:tester")
    ex = DistributedResultExchange(
        backend,
        router,
        "gw-test",
        {"registry": {"call_backlog_limit": backlog_limit}},
    )
    return ex, router, backend


async def _worker(router, msg_id, *, delay=0.05, result=None):
    """Stand in for the worker: publish a result after a beat, as the real one does."""

    async def _run():
        await asyncio.sleep(delay)
        await router.publish_result(SESSION, result or _rpc_result(msg_id))

    return asyncio.create_task(_run())


async def test_the_replica_receives_a_result_it_did_not_produce(real_redis):
    """The core of A2: the answer is published by someone else, and still comes back here."""
    ex, router, _ = await _exchange(real_redis)
    task = await _worker(router, 1)

    got = await ex.exchange(
        HOST,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        session_id=SESSION,
        subject="key:tester",
        rid="r1",
        timeout=5,
    )
    await task
    assert got == _rpc_result(1)


async def test_a_result_published_before_the_wait_begins_is_not_missed(real_redis):
    """The ordering property the whole design rests on.

    The dangerous race is a worker that answers between the dispatch and the start of the
    read — the result is already on the stream by the time we begin listening. Because the
    cursor is captured *before* dispatching, that result is still ahead of the cursor and is
    found. The natural-looking alternative (start reading, then publish) loses exactly these.

    Simulated by making the answer land *inside* the publish call, which is the tightest
    version of the race and cannot be hit by sleeping.
    """
    ex, router, backend = await _exchange(real_redis)

    original = backend.publish_tool_call

    async def _publish_and_answer_instantly(**kwargs):
        await original(**kwargs)
        # The worker got there first: the result exists before the wait loop starts.
        await router.publish_result(SESSION, _rpc_result(kwargs["message"]["id"]))

    backend.publish_tool_call = _publish_and_answer_instantly

    got = await ex.exchange(
        HOST,
        {"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        session_id=SESSION,
        subject="key:tester",
        rid="r2",
        timeout=5,
    )
    assert got == _rpc_result(7), "a result that landed before the read began was missed"


async def test_a_stale_result_with_a_recycled_id_is_not_mistaken_for_this_answer(real_redis):
    """JSON-RPC ids are chosen by the client and may repeat within a session.

    Reading the stream from `0` instead of from a cursor would match the *previous* request's
    result and return it as this one's — silently, and with plausible-looking content. This
    pins that the cursor is doing its job.
    """
    ex, router, _ = await _exchange(real_redis)

    # An earlier exchange on this session already answered id=1.
    await router.publish_result(SESSION, _rpc_result(1, {"content": [{"type": "text", "text": "STALE"}]}))

    task = await _worker(router, 1, delay=0.05, result=_rpc_result(1, {"content": [{"type": "text", "text": "FRESH"}]}))
    got = await ex.exchange(
        HOST,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        session_id=SESSION,
        subject="key:tester",
        rid="r3",
        timeout=5,
    )
    await task
    assert got["result"]["content"][0]["text"] == "FRESH", "matched a stale result from an earlier request"


async def test_another_requests_result_is_left_on_the_stream(real_redis):
    """Two requests in flight on one session must each get their own answer, and neither may
    consume the other's — the stream is shared, the correlation is not."""
    ex, router, _ = await _exchange(real_redis)

    await _worker(router, 2, delay=0.02)
    await _worker(router, 3, delay=0.04)

    got_3, got_2 = await asyncio.gather(
        ex.exchange(
            HOST,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            session_id=SESSION,
            subject="key:tester",
            rid="r4",
            timeout=5,
        ),
        ex.exchange(
            HOST,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            session_id=SESSION,
            subject="key:tester",
            rid="r5",
            timeout=5,
        ),
    )
    assert got_3["id"] == 3 and got_2["id"] == 2


async def test_no_worker_times_out_rather_than_hanging(real_redis):
    """Nothing publishes. The wait must end, and end as a timeout — not as a failed tool
    call, because the call may still be running upstream."""
    ex, _, _ = await _exchange(real_redis)

    with pytest.raises(ExchangeTimeout) as exc:
        await ex.exchange(
            HOST,
            {"jsonrpc": "2.0", "id": 99, "method": "tools/call"},
            session_id=SESSION,
            subject="key:tester",
            rid="r6",
            timeout=0.5,
        )
    assert "may still be running" in str(exc.value), "the message must not imply the call failed"


async def test_a_notification_does_not_wait_for_an_answer_that_never_comes(real_redis):
    """A message with no id has no response, so waiting for one would hang until the
    deadline on every notification."""
    ex, _, _ = await _exchange(real_redis)

    got = await asyncio.wait_for(
        ex.exchange(
            HOST,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session_id=SESSION,
            subject="key:tester",
            rid="r7",
            timeout=30,
        ),
        timeout=2,  # would blow up long before the 30s exchange timeout if it waited
    )
    assert got is None


async def test_a_backed_up_device_sheds_before_publishing(real_redis):
    """Admission control (F-06) applies to this transport too. A call added to a stream the
    worker is not draining gets trimmed at MAXLEN and surfaces only as a timeout, so the
    backlog check must happen before the publish, not after."""
    ex, _, backend = await _exchange(real_redis, backlog_limit=1)
    # Backlog is consumer-group *lag*, not stream length: entries only count as queued once
    # a group exists to be behind on them. Without the group (no worker has ever attached)
    # the signal is legitimately 0, so the group has to be created for this to mean anything.
    await real_redis.xgroup_create(KEYS.device_calls(HOST), KEYS.device_calls_group(HOST), id="0", mkstream=True)
    for _ in range(2):
        await backend.publish_tool_call(
            hostname=HOST,
            request_id="pre",
            session_id=SESSION,
            gateway_id="gw-test",
            message={"jsonrpc": "2.0", "id": 0, "method": "tools/list"},
        )

    with pytest.raises(ExchangeUnavailable) as exc:
        await ex.exchange(
            HOST,
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call"},
            session_id=SESSION,
            subject="key:tester",
            rid="r8",
            timeout=5,
        )
    assert exc.value.status_code == 429


async def test_the_call_really_reaches_the_devices_stream(real_redis):
    """The exchange must actually dispatch. A test that only checks the result could pass
    against an implementation that published nothing and read a result someone else left."""
    ex, router, _ = await _exchange(real_redis)
    await _worker(router, 11, delay=0.05)

    await ex.exchange(
        HOST,
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call"},
        session_id=SESSION,
        subject="key:tester",
        rid="r9",
        timeout=5,
    )
    depth = await real_redis.xlen(KEYS.device_calls(HOST))
    assert depth == 1, "the tool call should have been published to the device's stream"
