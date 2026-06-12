# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for the device auth adapters (F-42 OAuth2 variants, F-43 API-key placements)."""

from unittest.mock import patch

import httpx
import pytest

from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway.core.translator import McpManifest, McpTool
from device_mcp_gateway.pods.device_pod import DevicePod

# --- F-43: API-key placements ------------------------------------------------


@pytest.mark.asyncio
async def test_api_key_header_default():
    auth = ApiKeyAuth(api_key="k", header_name="X-API-Key")
    assert await auth.get_headers() == {"X-API-Key": "k"}
    mat = await auth.apply()
    assert mat.headers == {"X-API-Key": "k"} and mat.params == {} and mat.cookies == {}


@pytest.mark.asyncio
async def test_api_key_query_placement():
    auth = ApiKeyAuth(api_key="k", location="query", name="apikey")
    assert await auth.get_headers() == {}  # not a header
    mat = await auth.apply()
    assert mat.params == {"apikey": "k"} and mat.headers == {}


@pytest.mark.asyncio
async def test_api_key_cookie_placement():
    auth = ApiKeyAuth(api_key="k", location="cookie", name="session")
    mat = await auth.apply()
    assert mat.cookies == {"session": "k"} and mat.headers == {}


@pytest.mark.asyncio
async def test_api_key_value_prefix_bearer():
    auth = ApiKeyAuth(api_key="k", location="header", name="Authorization", value_prefix="Bearer ")
    assert await auth.get_headers() == {"Authorization": "Bearer k"}


def test_api_key_default_names_per_location():
    assert ApiKeyAuth("k", location="query").name == "api_key"
    assert ApiKeyAuth("k", location="cookie").name == "api_key"
    assert ApiKeyAuth("k", location="header").name == "X-API-Key"


def test_api_key_invalid_location_raises():
    with pytest.raises(ValueError):
        ApiKeyAuth("k", location="body")


def test_api_key_round_trips_through_dict():
    auth = ApiKeyAuth(api_key="k", location="query", name="apikey", value_prefix="v ")
    clone = ApiKeyAuth.from_dict(auth.to_dict())
    assert (clone.location, clone.name, clone.value_prefix, clone.api_key) == ("query", "apikey", "v ", "k")


def test_api_key_legacy_header_name_round_trips():
    # An old persisted config (header_name only, no location) must still parse to a header key.
    clone = ApiKeyAuth.from_dict({"api_key": "k", "header_name": "X-Custom"})
    assert clone.location == "header" and clone.name == "X-Custom"


# --- F-42: OAuth2 variants ---------------------------------------------------


def _oauth(**over):
    base = dict(token_endpoint="https://auth/t", client_id="cid", client_secret="sec")
    base.update(over)
    return OAuth2Auth(**base)


def test_oauth_request_body_includes_client_creds():
    data, basic = _oauth()._build_request()
    assert data["grant_type"] == "client_credentials"
    assert data["client_id"] == "cid" and data["client_secret"] == "sec"
    assert basic is None


def test_oauth_basic_style_omits_creds_from_body():
    data, basic = _oauth(auth_style="basic")._build_request()
    assert "client_id" not in data and "client_secret" not in data
    assert isinstance(basic, httpx.BasicAuth)


def test_oauth_audience_and_extra_params():
    data, _ = _oauth(audience="https://api", extra_params={"resource": "r1"})._build_request()
    assert data["audience"] == "https://api"
    assert data["resource"] == "r1"


def test_oauth_password_grant_body():
    data, _ = _oauth(grant_type="password", username="u", password="p")._build_request()
    assert data["grant_type"] == "password"
    assert data["username"] == "u" and data["password"] == "p"


def test_oauth_refresh_token_grant_body():
    data, _ = _oauth(grant_type="refresh_token", refresh_token="rt")._build_request()
    assert data["grant_type"] == "refresh_token" and data["refresh_token"] == "rt"


def test_oauth_invalid_grant_and_style_raise():
    with pytest.raises(ValueError):
        _oauth(grant_type="authorization_code")
    with pytest.raises(ValueError):
        _oauth(auth_style="digest")


def test_oauth_round_trips_through_dict():
    auth = _oauth(grant_type="password", auth_style="basic", audience="a", username="u", password="p")
    clone = OAuth2Auth.from_dict(auth.to_dict())
    assert (clone.grant_type, clone.auth_style, clone.audience, clone.username) == ("password", "basic", "a", "u")


@pytest.mark.asyncio
async def test_oauth_get_headers_fetches_bearer():
    auth = _oauth()

    async def fake_post(self, url, **kwargs):
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600}, request=httpx.Request("POST", url))

    with patch("httpx.AsyncClient.post", fake_post):
        headers = await auth.get_headers()
    assert headers == {"Authorization": "Bearer tok"}


# --- end-to-end through the pod ----------------------------------------------


def _get_pod(auth):
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
                path="/items",
            )
        ],
    )
    return DevicePod(hostname="dev", manifest=manifest, transport="sse", base_url="http://dev.local", auth=auth)


@pytest.mark.asyncio
async def test_pod_sends_query_api_key_on_request():
    captured = {}

    async def fake_request(self, method, url, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, content=b"{}", headers={"content-type": "application/json"})

    with patch("httpx.AsyncClient.request", fake_request):
        pod = _get_pod(ApiKeyAuth(api_key="secret", location="query", name="apikey"))
        await pod._tool_dispatch["t"]()

    assert captured["params"] == {"apikey": "secret"}


@pytest.mark.asyncio
async def test_pod_sends_cookie_api_key_on_request():
    captured = {}

    async def fake_request(self, method, url, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, content=b"{}", headers={"content-type": "application/json"})

    with patch("httpx.AsyncClient.request", fake_request):
        pod = _get_pod(ApiKeyAuth(api_key="secret", location="cookie", name="sid"))
        await pod._tool_dispatch["t"]()

    assert captured["cookies"] == {"sid": "secret"}
