# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for optional OpenTelemetry tracing (F-14).

These exercise the always-available no-op behaviour and the cross-process carrier
plumbing. The "tracing active" path needs the [otel] extra; where it isn't
installed, init_tracing must degrade to OFF rather than raise — which is asserted.
"""

import importlib.util

import fakeredis.aioredis
import pytest

from device_mcp_gateway.observability import tracing
from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend

_OTEL_INSTALLED = importlib.util.find_spec("opentelemetry") is not None


@pytest.fixture(autouse=True)
def _reset_tracing():
    tracing._reset_for_tests()
    yield
    tracing._reset_for_tests()


def test_disabled_by_default():
    assert tracing.init_tracing({}, "svc") is False
    assert tracing.tracing_enabled() is False
    assert tracing.init_tracing({"tracing": {"enabled": False}}, "svc") is False


def test_start_span_is_noop_when_disabled():
    with tracing.start_span("x", attributes={"a": 1}) as span:
        assert span is None  # nothing created, but the block still runs


def test_inject_carrier_unchanged_when_disabled():
    # No traceparent is added, and the carrier is returned for the caller to pass on.
    assert tracing.inject_carrier() == {}
    assert tracing.inject_carrier({"existing": "v"}) == {"existing": "v"}


def test_start_span_from_carrier_is_noop_when_disabled():
    with tracing.start_span_from_carrier("x", {"traceparent": "whatever"}) as span:
        assert span is None


@pytest.mark.skipif(_OTEL_INSTALLED, reason="covers the missing-dependency degrade path only")
def test_enabled_without_otel_degrades_to_off():
    # Asking for tracing without the [otel] extra installed must NOT raise — it
    # logs a warning and stays a no-op.
    assert tracing.init_tracing({"tracing": {"enabled": True}}, "svc") is False
    assert tracing.tracing_enabled() is False


@pytest.mark.skipif(not _OTEL_INSTALLED, reason="requires the [otel] extra")
def test_enabled_with_otel_round_trips_context():
    assert tracing.init_tracing({"tracing": {"enabled": True}}, "svc") is True
    with tracing.start_span("parent"):
        carrier = tracing.inject_carrier()
    assert "traceparent" in carrier  # W3C context was injected


@pytest.mark.asyncio
async def test_publish_tool_call_carries_traceparent_field():
    # The propagation field rides on the stream entry even when its value is empty
    # (tracing off) so the worker can always read fields.get("traceparent").
    backend = RedisRegistryBackend(fakeredis.aioredis.FakeRedis(decode_responses=True))
    await backend.publish_tool_call(
        "dev1", "r1", "s1", "gw", {"method": "tools/call"}, rid="abc", traceparent="00-trace-span-01"
    )
    entries = await backend._r.xrange("device:dev1:calls")
    assert entries, "expected one stream entry"
    _id, fields = entries[0]
    assert fields["traceparent"] == "00-trace-span-01"
    assert fields["rid"] == "abc"
