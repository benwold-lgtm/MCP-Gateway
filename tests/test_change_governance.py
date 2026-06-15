# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""F-41 — breaking-change governance for the generated tool set.

Covers the pure classifier (:func:`diff_tools`) across the compatible/breaking
permutations, the recording side effects (:func:`record_tool_change` → metric +
audit), and the ``tools_revision`` round-trip on ``DeviceConfig``.
"""

from device_mcp_gateway import metrics
from device_mcp_gateway.core.manifest_diff import diff_tools, record_tool_change
from device_mcp_gateway.shared.registry_backend import DeviceConfig


def _tool(name, method="GET", props=None, required=None):
    schema = {"type": "object"}
    if props is not None:
        schema["properties"] = {p: {"type": "string"} for p in props}
    if required is not None:
        schema["required"] = list(required)
    return {"name": name, "method": method, "schema": schema}


# --- diff_tools: no-op / additive (compatible) ------------------------------


def test_identical_sets_are_empty_noop():
    tools = [_tool("a"), _tool("b", "POST")]
    diff = diff_tools(tools, tools)
    assert diff.empty
    assert not diff.breaking


def test_added_tool_is_compatible():
    diff = diff_tools([_tool("a")], [_tool("a"), _tool("b", "POST")])
    assert diff.added == ["b"]
    assert diff.removed == [] and diff.changed == []
    assert diff.breaking is False
    assert not diff.empty


def test_added_optional_parameter_is_compatible():
    old = [_tool("a", props=["x"])]
    new = [_tool("a", props=["x", "y"])]  # y added, not required
    diff = diff_tools(old, new)
    assert diff.changed == ["a"]
    assert diff.breaking is False


def test_loosened_required_is_compatible():
    old = [_tool("a", props=["x", "y"], required=["x", "y"])]
    new = [_tool("a", props=["x", "y"], required=["x"])]  # y no longer required
    diff = diff_tools(old, new)
    assert diff.changed == ["a"]
    assert diff.breaking is False


# --- diff_tools: breaking ---------------------------------------------------


def test_removed_tool_is_breaking():
    diff = diff_tools([_tool("a"), _tool("b")], [_tool("a")])
    assert diff.removed == ["b"]
    assert diff.breaking is True
    assert any("removed" in r for r in diff.breaking_reasons)


def test_removed_parameter_is_breaking():
    old = [_tool("a", props=["x", "y"])]
    new = [_tool("a", props=["x"])]
    diff = diff_tools(old, new)
    assert diff.changed == ["a"]
    assert diff.breaking is True
    assert any("parameter(s) removed" in r for r in diff.breaking_reasons)


def test_newly_required_parameter_is_breaking():
    old = [_tool("a", props=["x", "y"], required=["x"])]
    new = [_tool("a", props=["x", "y"], required=["x", "y"])]
    diff = diff_tools(old, new)
    assert diff.breaking is True
    assert any("newly required" in r for r in diff.breaking_reasons)


def test_method_change_is_breaking():
    diff = diff_tools([_tool("a", "GET")], [_tool("a", "POST")])
    assert diff.changed == ["a"]
    assert diff.breaking is True
    assert any("method GET→POST" in r for r in diff.breaking_reasons)


def test_breaking_and_additive_together():
    old = [_tool("keep"), _tool("gone")]
    new = [_tool("keep"), _tool("fresh", "POST")]
    diff = diff_tools(old, new)
    assert diff.added == ["fresh"] and diff.removed == ["gone"]
    assert diff.breaking is True  # removal dominates


def test_accepts_mcptool_like_objects():
    class _T:
        def __init__(self, name, method, schema):
            self.name, self.method, self.schema = name, method, schema

    old = [_T("a", "GET", {"properties": {"x": {}}})]
    new = [_T("a", "GET", {"properties": {}})]  # removed x → breaking
    diff = diff_tools(old, new)
    assert diff.breaking is True


# --- record_tool_change: side effects ---------------------------------------


def _counter_value(hostname, breaking):
    return metrics.device_tools_changed_total.labels(hostname=hostname, breaking=breaking)._value.get()


def test_record_emits_metric_and_returns_diff(caplog):
    before = _counter_value("h1", "true")
    diff = record_tool_change("h1", [_tool("a"), _tool("b")], [_tool("a")])
    assert diff.breaking is True
    assert _counter_value("h1", "true") == before + 1


def test_record_noop_when_unchanged():
    tools = [_tool("a")]
    before = _counter_value("h2", "false")
    diff = record_tool_change("h2", tools, tools)
    assert diff.empty
    # No metric bump on a no-op spec edit.
    assert _counter_value("h2", "false") == before


def test_record_compatible_labels_false():
    before = _counter_value("h3", "false")
    diff = record_tool_change("h3", [_tool("a")], [_tool("a"), _tool("b")])
    assert diff.breaking is False
    assert _counter_value("h3", "false") == before + 1


# --- tools_revision persistence ---------------------------------------------


def test_tools_revision_round_trips_through_redis_hash():
    cfg = DeviceConfig(hostname="h", base_url="http://h", tools_revision=7)
    restored = DeviceConfig.from_redis_hash(cfg.to_redis_hash())
    assert restored.tools_revision == 7


def test_tools_revision_defaults_zero_for_legacy_hash():
    # A hash written before F-41 has no tools_revision key.
    legacy = DeviceConfig(hostname="h", base_url="http://h").to_redis_hash()
    legacy.pop("tools_revision", None)
    assert DeviceConfig.from_redis_hash(legacy).tools_revision == 0
