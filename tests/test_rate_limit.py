# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Tests for rate-limiter client-IP resolution and shared storage (S2 finding F4).

The in-memory per-replica limiter keyed on the socket peer IP misbehaves behind
an ingress (all clients collapse to the proxy IP) and doesn't share limits
across replicas. The key func now optionally trusts X-Forwarded-For, and
distributed mode derives a shared Redis storage URI.
"""

from types import SimpleNamespace

from device_mcp_gateway.main import _client_ip_key_func, _rate_limit_storage_uri


def _req(forwarded=None, peer="10.0.0.1"):
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


def test_trust_proxy_uses_leftmost_forwarded_ip():
    key = _client_ip_key_func(trust_proxy=True)
    assert key(_req(forwarded="203.0.113.5, 70.0.0.1, 10.0.0.1")) == "203.0.113.5"


def test_trust_proxy_falls_back_to_peer_when_no_header():
    key = _client_ip_key_func(trust_proxy=True)
    assert key(_req(forwarded=None, peer="10.0.0.9")) == "10.0.0.9"


def test_untrusted_ignores_forwarded_header():
    key = _client_ip_key_func(trust_proxy=False)
    # Spoofed XFF must be ignored; key on the real socket peer.
    assert key(_req(forwarded="1.2.3.4", peer="10.0.0.1")) == "10.0.0.1"


def test_storage_uri_explicit_override_wins():
    cfg = {"gateway": {"rate_limit_storage_uri": "redis://custom:6379"}, "redis": {"url": "redis://other:6379"}}
    assert _rate_limit_storage_uri(cfg, "distributed") == "redis://custom:6379"


def test_storage_uri_distributed_derives_redis_url(monkeypatch):
    monkeypatch.delenv("MCP_REDIS_URL", raising=False)
    cfg = {"redis": {"url": "redis://r:6379/0"}}
    assert _rate_limit_storage_uri(cfg, "distributed") == "redis://r:6379/0"


def test_storage_uri_embedded_is_in_memory():
    assert _rate_limit_storage_uri({"redis": {"url": "redis://r:6379"}}, "embedded") is None
