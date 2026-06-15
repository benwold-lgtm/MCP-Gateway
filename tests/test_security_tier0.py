# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-0 security regression tests (F-38).

Covers the release-blocking security fixes:
  - F-02/F-29 SSRF URL policy (validate_target_url + route rejection + resources/read traversal)
  - F-25 tool-call header injection (reserved-header drop, CRLF, auth-header wins)
  - F-28 server-side tool-argument validation
  - F-26 schema-poisoning text sanitization
  - F-27 oversized upstream response cap

(F-23 fail-open auth + F-24 Redis-auth startup gates are covered in test_credentials.py.)
"""

from unittest.mock import patch

import pytest

from device_mcp_gateway.core.translator import SpecTranslator, _sanitize_text
from device_mcp_gateway.pods.device_pod import (
    _MAX_RESPONSE_BYTES,
    _sanitize_header_params,
    _validate_arguments,
    DevicePod,
)
from device_mcp_gateway.core.translator import McpManifest, McpTool
from device_mcp_gateway.security.url_policy import UrlPolicyError, validate_target_url

# --- F-02 SSRF: validate_target_url -----------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata (link-local)
        "http://127.0.0.1:8080/",  # loopback
        "http://localhost/",  # loopback by name
        "http://10.0.0.5/",  # private
        "http://192.168.1.1/",  # private
        "http://[::1]/",  # IPv6 loopback
        "file:///etc/passwd",  # bad scheme
        "ftp://example.com/",  # bad scheme
        "not-a-url",  # no host
    ],
)
def test_validate_target_url_blocks_unsafe(url):
    with pytest.raises(UrlPolicyError):
        validate_target_url(url, allow_private=False)


def test_validate_target_url_allows_public():
    # Public, resolvable host — should not raise.
    validate_target_url("https://example.com/api", allow_private=False)


def test_validate_target_url_allow_private_bypass():
    # With allow_private, internal targets are permitted (trusted device fleet).
    validate_target_url("http://127.0.0.1:9000/", allow_private=True)
    validate_target_url("http://10.1.2.3/", allow_private=True)


def test_register_route_rejects_ssrf(tmp_path, monkeypatch):
    """The POST /devices route returns 400 for a blocked base_url when private
    targets are not allowed (env override cleared)."""
    from fastapi.testclient import TestClient
    from device_mcp_gateway.main import create_app

    monkeypatch.delenv("MCP_ALLOW_PRIVATE_TARGETS", raising=False)
    cfg = {
        "registry": {"mode": "embedded"},
        "storage": {"db_path": str(tmp_path / "devices.db")},
        "security": {"allow_private_targets": False},
        "metrics": {"enabled": False},
    }
    app = create_app(override_config=cfg)
    client = TestClient(app)
    resp = client.post(
        "/v1/devices",
        json={"hostname": "evil", "base_url": "http://169.254.169.254/", "auth_type": "none"},
    )
    assert resp.status_code == 400
    assert "base_url" in resp.json()["detail"]


# --- F-25 header injection ---------------------------------------------------


def test_sanitize_header_params_drops_reserved_and_crlf():
    out = _sanitize_header_params(
        {
            "Authorization": "Bearer attacker",  # reserved → dropped
            "Host": "evil.example.com",  # reserved → dropped
            "X-Forwarded-For": "1.2.3.4",  # reserved → dropped
            "X-Custom": "ok",  # allowed
            "X-Bad": "a\r\nInjected: yes",  # CRLF → dropped
        }
    )
    assert out == {"X-Custom": "ok"}


@pytest.mark.asyncio
async def test_header_param_cannot_override_auth():
    """A header-located tool argument must not override the device's auth header."""
    from device_mcp_gateway.auth.api_key import ApiKeyAuth

    manifest = McpManifest(
        server_name="m",
        server_version="1",
        hostname="dev",
        tools=[
            McpTool(
                name="t",
                description="d",
                schema={"type": "object", "properties": {}},
                method="GET",
                path="/x",
                param_locations={"authorization": "header", "host": "header", "x_custom": "header"},
            )
        ],
    )
    captured = {}

    async def fake_request(self, method, url, **kwargs):
        captured["headers"] = kwargs.get("headers")

        class _R:
            status_code = 200
            content = b"{}"
            headers = {"content-type": "application/json"}

            def json(self):
                return {}

        return _R()

    with patch("httpx.AsyncClient.request", fake_request):
        pod = DevicePod(
            hostname="dev",
            manifest=manifest,
            transport="sse",
            base_url="http://dev.local",
            auth=ApiKeyAuth(api_key="real-token", header_name="Authorization"),
        )
        await pod._tool_dispatch["t"](authorization="attacker", host="evil", x_custom="ok")

    h = captured["headers"]
    assert h["Authorization"] == "real-token"  # auth wins, not "attacker"
    assert "host" not in {k.lower() for k in h}  # reserved dropped
    assert h.get("x_custom") == "ok"  # benign header preserved


# --- F-28 argument validation ------------------------------------------------


def test_validate_arguments_rejects_missing_required():
    schema = {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}
    assert _validate_arguments(schema, {}) is not None  # missing required → error string
    assert _validate_arguments(schema, {"id": 5}) is None  # valid → None


def test_validate_arguments_rejects_wrong_type():
    schema = {"type": "object", "properties": {"id": {"type": "integer"}}}
    assert _validate_arguments(schema, {"id": "not-an-int"}) is not None


def test_validate_arguments_skips_invalid_schema():
    # A schema that isn't valid JSON Schema must not block the call (fail-open on validation).
    assert _validate_arguments({"type": 123}, {"anything": True}) is None


@pytest.mark.asyncio
async def test_tools_call_rejects_invalid_arguments():
    manifest = McpManifest(
        server_name="m",
        server_version="1",
        hostname="dev",
        tools=[
            McpTool(
                name="get_item",
                description="d",
                schema={"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
                method="GET",
                path="/items/{id}",
                param_locations={"id": "path"},
            )
        ],
    )
    pod = DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local")
    resp = await pod.call_tool(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_item", "arguments": {}}}
    )
    assert resp["error"]["code"] == -32602  # invalid params (missing required 'id')


# --- F-29 resources/read traversal ------------------------------------------


@pytest.mark.asyncio
async def test_resources_read_blocks_traversal():
    manifest = McpManifest(server_name="m", server_version="1", hostname="dev", tools=[])
    pod = DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local")
    resp = await pod.call_tool(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "device://dev/../../admin/keys"},
        }
    )
    assert resp["error"]["code"] == -32602  # invalid resource path


# --- F-26 schema-poisoning sanitization -------------------------------------


def test_sanitize_text_strips_obfuscation_and_caps():
    # zero-width + control + bidi chars removed; length capped with ellipsis.
    poisoned = "Safe tool​\x07‮INSTRUCTIONS"
    cleaned = _sanitize_text(poisoned)
    assert "​" not in cleaned and "\x07" not in cleaned and "‮" not in cleaned
    assert cleaned == "Safe toolINSTRUCTIONS"
    long = _sanitize_text("x" * 5000)
    assert len(long) == 1024 and long.endswith("…")


def test_translator_sanitizes_tool_description():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "T", "version": "1"},
        "paths": {
            "/x": {
                "get": {
                    "operationId": "getx",
                    "summary": "do x​\x07 now",  # contains zero-width + control char
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    manifest = SpecTranslator().translate(spec, "dev")
    desc = manifest.tools[0].description
    assert "​" not in desc and "\x07" not in desc
    assert desc == "do x now"


# --- F-27 oversized response cap --------------------------------------------


@pytest.mark.asyncio
async def test_oversized_response_is_capped():
    manifest = McpManifest(
        server_name="m",
        server_version="1",
        hostname="dev",
        tools=[
            McpTool(
                name="big",
                description="d",
                schema={"type": "object", "properties": {}},
                method="GET",
                path="/big",
            )
        ],
    )

    async def fake_request(self, method, url, **kwargs):
        class _R:
            status_code = 200
            content = b"x" * (_MAX_RESPONSE_BYTES + 1)
            headers = {"content-type": "application/json"}

            def json(self):
                return {}

        return _R()

    with patch("httpx.AsyncClient.request", fake_request):
        pod = DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local")
        result = await pod._tool_dispatch["big"]()
    # Normalized error envelope (F-39): ok=False, stable error.type, status carries 502.
    assert result["ok"] is False
    assert result["status"] == 502
    assert result["error"]["type"] == "response_too_large"
    assert "too large" in result["error"]["message"]
