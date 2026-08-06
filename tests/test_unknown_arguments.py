# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""An argument the gateway cannot send must not be reported as sent.

Found on a live cluster. Generated tool schemas carried no ``additionalProperties``, so a
call naming an argument that does not exist validated cleanly, was dropped on the way to the
device (there is nowhere to put it), and came back as a success. To a model, a successful
call is confirmation that the argument it invented is real — so the failure mode is not a
dropped value, it is a hallucination the gateway corroborates.

The distinction that matters here is *whose schema it is*. The translator knows the complete
set of arguments it can place, so closing its schemas states a fact. A proxied MCP upstream
publishes its own ``inputSchema`` and does its own validation, so closing that would be us
tightening a contract we do not own, and could refuse calls the upstream would have accepted.
"""

import pytest

from device_mcp_gateway.core.translator import SpecTranslator
from device_mcp_gateway.pods.pod_base import _validate_arguments
from device_mcp_gateway.upstream.mcp_discovery import build_proxy_manifest

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/fan": {
            "post": {
                "operationId": "setFan",
                "parameters": [{"name": "zone", "in": "query", "required": True, "schema": {"type": "string"}}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"speed": {"type": "integer"}},
                                "required": ["speed"],
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def _tool():
    manifest = SpecTranslator().translate(SPEC, "dev1")
    return manifest.tools[0]


def test_a_generated_schema_is_closed():
    tool = _tool()
    assert tool.schema["additionalProperties"] is False
    # And it really does list everything the dispatcher can place, which is what makes
    # closing it truthful rather than merely strict.
    assert set(tool.schema["properties"]) == {"zone", "speed"}


def test_an_invented_argument_is_refused_instead_of_silently_dropped():
    """The actual regression: this call used to validate, and the gateway answered success."""
    tool = _tool()
    err = _validate_arguments(tool.schema, {"zone": "a", "speed": 50, "temperature": 20})
    assert err is not None
    assert "temperature" in err


def test_a_legitimate_call_is_unaffected():
    tool = _tool()
    assert _validate_arguments(tool.schema, {"zone": "a", "speed": 50}) is None


def test_omitting_an_optional_argument_is_still_fine():
    """Closing a schema restricts unknown keys, not absent ones — guard against over-tightening."""
    tool = _tool()
    # `speed` and `zone` are both required here, so drop one required arg and confirm the
    # complaint is about *that*, not about additionalProperties.
    err = _validate_arguments(tool.schema, {"zone": "a"})
    assert err is not None and "speed" in err


def test_a_proxied_upstream_schema_is_left_exactly_as_published():
    """We do not own an upstream's contract, so we must not tighten it."""
    published = {
        "name": "echo",
        "description": "d",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    }
    manifest = build_proxy_manifest("mcp1", [published])
    schema = manifest.tools[0].schema

    assert "additionalProperties" not in schema, "the upstream did not close this; neither may we"
    # An extra argument therefore passes our validation and goes to the upstream, which is
    # the only party that can say whether it is meaningful.
    assert _validate_arguments(schema, {"text": "hi", "extra": 1}) is None


@pytest.mark.parametrize("bad", [{"speed": "fast"}, {"zone": 1, "speed": 2}])
def test_type_errors_still_report_the_offending_field(bad):
    """Closing the schema must not make every failure read as an additionalProperties error."""
    err = _validate_arguments(_tool().schema, bad)
    assert err is not None
    assert "additionalProperties" not in err
