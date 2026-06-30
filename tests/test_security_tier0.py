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
        "http://[::ffff:169.254.169.254]/latest/meta-data/",  # IPv4-mapped IPv6 → metadata (M-2)
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6 → loopback (M-2)
        "http://[::ffff:10.0.0.5]/",  # IPv4-mapped IPv6 → private (M-2)
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


@pytest.mark.asyncio
async def test_tool_param_named_like_closure_var_does_not_collide():
    """F-04: a tool whose OpenAPI parameter is literally named tool/auth/base_url/
    rate_limiter must dispatch normally, not raise 'got multiple values for argument'."""
    reserved = ["tool", "auth", "base_url", "rate_limiter"]
    manifest = McpManifest(
        server_name="m",
        server_version="1",
        hostname="dev",
        tools=[
            McpTool(
                name="t",
                description="d",
                schema={"type": "object", "properties": {k: {"type": "string"} for k in reserved}},
                method="GET",
                path="/x",
                param_locations={k: "query" for k in reserved},
            )
        ],
    )
    captured = {}

    async def fake_request(self, method, url, **kwargs):
        captured["params"] = kwargs.get("params")

        class _R:
            status_code = 200
            content = b"{}"
            headers = {"content-type": "application/json"}

            def json(self):
                return {}

        return _R()

    with patch("httpx.AsyncClient.request", fake_request):
        pod = DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local")
        # Before the factory fix this raised "got multiple values for argument 'tool'"
        # before any request was made; now it dispatches normally.
        await pod._tool_dispatch["t"](**{k: f"v_{k}" for k in reserved})

    # The request reached the wire with every reserved-named arg forwarded as a query param.
    assert captured["params"] == {k: f"v_{k}" for k in reserved}


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


# --- R1 / SSRF-1: redirect-following + worker fetch-time validation ----------


@pytest.mark.asyncio
async def test_ssrf_guard_transport_blocks_redirect_to_internal():
    """A validated public host that 302-redirects to an internal address must be
    rejected at the redirect hop, not followed (the F-02 redirect bypass)."""
    import httpx

    from device_mcp_gateway.security.url_policy import SsrfGuardTransport

    public_ip = "93.184.216.34"  # public IP literal — passes policy without DNS

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == public_ip:
            return httpx.Response(302, headers={"location": "http://127.0.0.1/latest/meta-data/"})
        return httpx.Response(200, text="REACHED INTERNAL")

    guard = SsrfGuardTransport(httpx.MockTransport(handler), allow_private=False)
    async with httpx.AsyncClient(transport=guard, follow_redirects=True) as client:
        with pytest.raises(UrlPolicyError):
            await client.get(f"http://{public_ip}/")


@pytest.mark.asyncio
async def test_ssrf_guard_transport_allows_public_hop():
    """The guard must not block a legitimate public request."""
    import httpx

    from device_mcp_gateway.security.url_policy import SsrfGuardTransport

    public_ip = "93.184.216.34"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    guard = SsrfGuardTransport(httpx.MockTransport(handler), allow_private=False)
    async with httpx.AsyncClient(transport=guard) as client:
        resp = await client.get(f"http://{public_ip}/")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ssrf_guard_transport_allow_private_follows_redirect():
    """With allow_private (trusted fleet), an internal redirect target is permitted."""
    import httpx

    from device_mcp_gateway.security.url_policy import SsrfGuardTransport

    public_ip = "93.184.216.34"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == public_ip:
            return httpx.Response(302, headers={"location": "http://127.0.0.1/ok"})
        return httpx.Response(200, text="internal-ok")

    guard = SsrfGuardTransport(httpx.MockTransport(handler), allow_private=True)
    async with httpx.AsyncClient(transport=guard, follow_redirects=True) as client:
        resp = await client.get(f"http://{public_ip}/")
    assert resp.status_code == 200
    assert resp.text == "internal-ok"


def test_device_pod_dispatch_client_does_not_follow_redirects():
    """The tool-dispatch hot path must not follow redirects (SSRF + header-leak via 3xx)."""
    manifest = McpManifest(server_name="m", server_version="1", hostname="dev")
    pod = DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local")
    assert pod._client().follow_redirects is False


# --- R1 / SSRF-2: OAuth2 token_endpoint is an outbound target ----------------


def test_register_route_rejects_ssrf_token_endpoint(tmp_path, monkeypatch):
    """An oauth2 device whose token_endpoint resolves to an internal address is
    refused — the gateway POSTs the client_secret there, so it is SSRF-sensitive."""
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
        json={
            "hostname": "oauthdev",
            "base_url": "https://example.com",
            "auth_type": "oauth2",
            "auth": {
                "token_endpoint": "http://169.254.169.254/token",
                "client_id": "id",
                "client_secret": "secret",
            },
        },
    )
    assert resp.status_code == 400
    assert "token_endpoint" in resp.json()["detail"]


# --- R4: egress residuals (dispatch re-validation + OAuth2 token-fetch guard) -


def test_device_pod_dispatch_client_is_ssrf_guarded():
    """The dispatch client re-validates the target host on every call (DNS-rebind of a
    registered device) while still not following redirects (header-leak)."""
    from device_mcp_gateway.security.url_policy import SsrfGuardTransport

    manifest = McpManifest(server_name="m", server_version="1", hostname="dev")
    pod = DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local")
    client = pod._client()
    assert isinstance(client._transport, SsrfGuardTransport)
    assert client.follow_redirects is False


@pytest.mark.asyncio
async def test_oauth2_token_fetch_blocks_private_endpoint(monkeypatch):
    """OAuth2 token fetch is SSRF-guarded: a token_endpoint that resolves to a metadata/
    internal address is refused at fetch time, so client_secret can't be exfiltrated by a
    DNS-rebind after registration."""
    from device_mcp_gateway.auth.oauth2 import OAuth2Auth

    monkeypatch.delenv("MCP_ALLOW_PRIVATE_TARGETS", raising=False)
    auth = OAuth2Auth(token_endpoint="http://169.254.169.254/token", client_id="id", client_secret="secret")
    with pytest.raises(UrlPolicyError):
        await auth.ensure_token()


@pytest.mark.asyncio
async def test_oauth2_configure_egress_allows_private_when_enabled(monkeypatch):
    """A trusted-fleet override (allow_private=True, propagated from the pod) lets the
    token fetch reach a private endpoint — it then fails on connection, NOT on policy."""
    from device_mcp_gateway.auth.oauth2 import OAuth2Auth

    monkeypatch.delenv("MCP_ALLOW_PRIVATE_TARGETS", raising=False)
    # 127.0.0.1:1 — loopback, refused fast (no slow connect to a metadata IP).
    auth = OAuth2Auth(token_endpoint="http://127.0.0.1:1/token", client_id="id", client_secret="secret")
    auth.configure_egress(allow_private=True)
    with pytest.raises(Exception) as ei:
        await auth.ensure_token()
    assert not isinstance(ei.value, UrlPolicyError)  # got past the policy, failed to connect


def test_device_pod_propagates_egress_policy_to_oauth2_auth():
    """The pod pushes its allow_private posture into an auth handler that makes its own
    outbound calls, so the OAuth2 token fetch shares the dispatch egress policy."""
    from device_mcp_gateway.auth.oauth2 import OAuth2Auth

    auth = OAuth2Auth(token_endpoint="https://idp.example.com/token", client_id="id", client_secret="secret")
    manifest = McpManifest(server_name="m", server_version="1", hostname="dev")
    DevicePod(
        hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local", auth=auth, allow_private=True
    )
    assert auth._allow_private is True
