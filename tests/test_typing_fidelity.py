# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for tool-gen typing fidelity (F-47, refines F-04).

Covers: oneOf/anyOf exclusivity preserved (not flattened), OpenAPI 3.0 nullable
normalized to a JSON-Schema nullable type, discriminator/example pass-through, and
required reconciled against surviving properties.
"""

from device_mcp_gateway.core.translator import SpecTranslator


def _t():
    return SpecTranslator()


def _spec(paths):
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1.0.0"}, "paths": paths}


# --- _resolve_schema normalization -------------------------------------------


def test_oneof_is_preserved_not_flattened():
    schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
    out = _t()._resolve_schema(schema)
    assert "oneOf" in out
    assert [b["type"] for b in out["oneOf"]] == ["string", "integer"]
    assert "properties" not in out  # not collapsed to a flat union


def test_anyof_is_preserved():
    out = _t()._resolve_schema({"anyOf": [{"type": "string"}, {"type": "null"}]})
    assert "anyOf" in out and len(out["anyOf"]) == 2


def test_nullable_string_becomes_nullable_type():
    out = _t()._resolve_schema({"type": "string", "nullable": True})
    assert out["type"] == ["string", "null"]
    assert "nullable" not in out  # OpenAPI-only keyword stripped


def test_nullable_on_oneof_adds_null_branch():
    out = _t()._resolve_schema({"oneOf": [{"type": "string"}, {"type": "integer"}], "nullable": True})
    assert {"type": "null"} in out["oneOf"]


def test_discriminator_and_example_pass_through():
    schema = {
        "type": "object",
        "properties": {"kind": {"type": "string"}},
        "discriminator": {"propertyName": "kind"},
        "example": {"kind": "a"},
    }
    out = _t()._resolve_schema(schema)
    assert out["discriminator"] == {"propertyName": "kind"}
    assert out["example"] == {"kind": "a"}


def test_required_reconciled_against_properties():
    # `phantom` is required but not a property → it must be dropped from required.
    out = _t()._resolve_schema(
        {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a", "phantom"]}
    )
    assert out["required"] == ["a"]


def test_required_dropped_entirely_when_none_survive():
    out = _t()._resolve_schema({"type": "object", "properties": {}, "required": ["gone"]})
    assert "required" not in out


# --- through translate() -----------------------------------------------------


def test_body_property_oneof_survives_into_tool_schema():
    spec = _spec(
        {
            "/x": {
                "post": {
                    "operationId": "make_x",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"payload": {"oneOf": [{"type": "string"}, {"type": "integer"}]}},
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        }
    )
    tool = _t().translate(spec, "h").tools[0]
    assert "oneOf" in tool.schema["properties"]["payload"]


def test_top_level_oneof_body_unions_branch_properties():
    # A oneOf body still yields flat tool args (union of branch properties), so calls work.
    spec = _spec(
        {
            "/y": {
                "post": {
                    "operationId": "make_y",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "oneOf": [
                                        {"type": "object", "properties": {"a": {"type": "string"}}},
                                        {"type": "object", "properties": {"b": {"type": "integer"}}},
                                    ]
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        }
    )
    tool = _t().translate(spec, "h").tools[0]
    assert "a" in tool.schema["properties"] and "b" in tool.schema["properties"]
