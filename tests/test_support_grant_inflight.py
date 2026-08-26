# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §8 — revocation interrupts in-flight work, in isolation.

Two layers: `InFlightSupportGrantCalls` (the plain registry) and `track_support_grant_inflight`
(the FastAPI dependency that wires a real asyncio task into it). The dependency is a generator
FastAPI drives via its DI machinery in production; here it's driven directly — calling
`__anext__()` is exactly what FastAPI does, and doing it by hand proves the exact cancellation/
audit/cleanup behaviour without depending on ASGI transport timing. The full HTTP-level,
same-process revoke-cancels-a-real-request proof lives in
`test_support_grant_inflight_authentication.py`.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from device_mcp_gateway.rbac import Principal, track_support_grant_inflight
from device_mcp_gateway.support_grant_inflight import InFlightSupportGrantCalls, support_grant_inflight_registry

# --- InFlightSupportGrantCalls ------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_registered_task_is_cancelled_by_cancel_all():
    registry = InFlightSupportGrantCalls()
    started = asyncio.Event()

    async def _hang():
        started.set()
        await asyncio.sleep(100)

    task = asyncio.ensure_future(_hang())
    registry.register("grant-1", task)
    await started.wait()

    count = registry.cancel_all("grant-1")
    assert count == 1
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_cancel_all_on_an_unknown_grant_returns_zero():
    registry = InFlightSupportGrantCalls()
    assert registry.cancel_all("no-such-grant") == 0


@pytest.mark.asyncio
async def test_unregister_removes_the_task_so_a_later_revoke_does_not_touch_it():
    registry = InFlightSupportGrantCalls()

    async def _noop():
        return None

    task = asyncio.ensure_future(_noop())
    registry.register("grant-1", task)
    await task
    registry.unregister("grant-1", task)

    assert registry.cancel_all("grant-1") == 0


@pytest.mark.asyncio
async def test_a_done_task_is_not_double_cancelled():
    registry = InFlightSupportGrantCalls()

    async def _noop():
        return None

    task = asyncio.ensure_future(_noop())
    registry.register("grant-1", task)
    await task  # finishes on its own before revoke

    assert registry.cancel_all("grant-1") == 0


@pytest.mark.asyncio
async def test_two_tasks_under_the_same_grant_are_both_cancelled():
    registry = InFlightSupportGrantCalls()
    started = asyncio.Event()
    count_started = 0

    async def _hang():
        nonlocal count_started
        count_started += 1
        if count_started == 2:
            started.set()
        await asyncio.sleep(100)

    t1 = asyncio.ensure_future(_hang())
    t2 = asyncio.ensure_future(_hang())
    registry.register("grant-1", t1)
    registry.register("grant-1", t2)
    await started.wait()

    assert registry.cancel_all("grant-1") == 2


@pytest.mark.asyncio
async def test_cancelling_one_grant_does_not_touch_another():
    registry = InFlightSupportGrantCalls()
    started = asyncio.Event()

    async def _hang():
        started.set()
        await asyncio.sleep(100)

    other = asyncio.ensure_future(_hang())
    registry.register("grant-other", other)
    await started.wait()

    assert registry.cancel_all("grant-1") == 0
    assert not other.done()
    other.cancel()
    with pytest.raises(asyncio.CancelledError):
        await other


def test_the_registry_accessor_lazily_attaches_one_instance_per_app_state():
    state = SimpleNamespace()
    first = support_grant_inflight_registry(state)
    second = support_grant_inflight_registry(state)
    assert first is second


# --- track_support_grant_inflight (the dependency, driven directly) -----------------------


def _request_with_principal(principal: Principal | None) -> SimpleNamespace:
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace()),
        state=SimpleNamespace(principal=principal, request_id="rid-1"),
        method="GET",
        url=SimpleNamespace(path="/v1/devices"),
    )


@pytest.mark.asyncio
async def test_a_non_support_grant_principal_is_a_no_op():
    principal = Principal(subject="key:admin", scopes=frozenset({"devices:read"}), auth_method="api_key")
    request = _request_with_principal(principal)

    gen = track_support_grant_inflight(request)
    await gen.__anext__()
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()

    registry = support_grant_inflight_registry(request.app.state)
    assert registry.cancel_all("anything") == 0


@pytest.mark.asyncio
async def test_a_support_grant_principal_registers_the_current_task_while_the_route_runs():
    principal = Principal(
        subject="oidc:provider#op1",
        scopes=frozenset({"devices:read"}),
        auth_method="support_grant",
        support_grant_id="grant-42",
    )
    request = _request_with_principal(principal)
    registry = support_grant_inflight_registry(request.app.state)
    started = asyncio.Event()
    release = asyncio.Event()

    async def _run():
        gen = track_support_grant_inflight(request)
        await gen.__anext__()
        started.set()
        await release.wait()  # stands in for "the route is still executing"
        with pytest.raises(StopAsyncIteration):
            await gen.__anext__()

    task = asyncio.ensure_future(_run())
    await started.wait()
    registered_while_running = len(registry._by_grant.get("grant-42", set()))
    release.set()
    await task

    # registered while the "route" was running, unregistered once it finished
    assert registered_while_running == 1
    assert registry.cancel_all("grant-42") == 0


@pytest.mark.asyncio
async def test_cancelling_the_wrapped_task_raises_through_the_generator_and_still_unregisters():
    principal = Principal(
        subject="oidc:provider#op1",
        scopes=frozenset({"devices:read"}),
        auth_method="support_grant",
        support_grant_id="grant-7",
    )
    request = _request_with_principal(principal)
    registry = support_grant_inflight_registry(request.app.state)
    started = asyncio.Event()

    async def _handler():
        gen = track_support_grant_inflight(request)
        await gen.__anext__()
        started.set()
        try:
            await asyncio.sleep(100)
        except BaseException as exc:  # noqa: BLE001 - re-raise into the generator, as FastAPI would
            with pytest.raises(asyncio.CancelledError):
                await gen.athrow(exc)
            raise

    task = asyncio.ensure_future(_handler())
    await started.wait()

    count = registry.cancel_all("grant-7")
    assert count == 1
    with pytest.raises(asyncio.CancelledError):
        await task

    # the finally-unregister ran even though the generator raised
    assert registry.cancel_all("grant-7") == 0
