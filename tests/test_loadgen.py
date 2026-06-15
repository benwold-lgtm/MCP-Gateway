# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for the load-test harness pure helpers (F-22).

The networked workloads need a live gateway, but the parsing / percentile / stats
logic is pure and worth pinning so the baseline numbers can be trusted.
"""

import math

import pytest

from tools.loadtest.loadgen import (
    Stats,
    build_parser,
    format_report,
    parse_sse_endpoint,
    parse_sse_message,
    percentile,
)


def test_percentile_nearest_rank():
    s = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    assert percentile(s, 50) == 50
    assert percentile(s, 90) == 90
    assert percentile(s, 99) == 100
    assert percentile(s, 100) == 100
    assert percentile(s, 0) == 10


def test_percentile_empty_is_nan():
    assert math.isnan(percentile([], 99))


def test_parse_sse_endpoint_extracts_url():
    block = "event: endpoint\ndata: /v1/devices/dev1/messages?session_id=abc\n"
    assert parse_sse_endpoint(block) == "/v1/devices/dev1/messages?session_id=abc"


def test_parse_sse_endpoint_ignores_other_events():
    assert parse_sse_endpoint('event: message\ndata: {"x": 1}\n') is None
    assert parse_sse_endpoint(": keep-alive\n") is None


def test_parse_sse_message_parses_json():
    block = 'event: message\ndata: {"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}\n'
    parsed = parse_sse_message(block)
    assert parsed is not None and parsed["result"] == {"ok": True}


def test_parse_sse_message_rejects_endpoint_and_bad_json():
    assert parse_sse_message("event: endpoint\ndata: /x\n") is None
    assert parse_sse_message("event: message\ndata: not-json\n") is None


def test_stats_report_shape_and_rates():
    st = Stats()
    for ms in (10.0, 20.0, 30.0, 40.0):
        st.record_ok(ms)
    st.record_error("timeout")
    st.record_error("post_429")
    rep = st.report()
    assert rep["requests"] == 6
    assert rep["ok"] == 4
    assert rep["errors"] == 2
    assert rep["timeouts"] == 1
    assert rep["error_rate"] == pytest.approx(2 / 6)
    assert rep["error_kinds"] == {"post_429": 1, "timeout": 1}
    assert rep["latency_ms"]["p50"] is not None
    # report renders without error
    assert "load baseline" in format_report(rep, "toolcall")


def test_parser_toolcall_requires_device_and_tool():
    parser = build_parser()
    args = parser.parse_args(["toolcall", "--device", "d", "--tool", "t"])
    assert args.workload == "toolcall" and args.device == "d" and args.tool == "t"
