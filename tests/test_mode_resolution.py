# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for registry-mode resolution and the split-brain guard (S2 finding F7).

The gateway and worker must agree on the mode. MCP_REGISTRY_MODE overrides the
config file, and the worker refuses to start unless the resolved mode is
distributed.
"""

from device_mcp_gateway.cfg import resolve_mode


def test_resolve_mode_defaults_to_embedded(monkeypatch):
    monkeypatch.delenv("MCP_REGISTRY_MODE", raising=False)
    assert resolve_mode({}) == "embedded"


def test_resolve_mode_reads_config(monkeypatch):
    monkeypatch.delenv("MCP_REGISTRY_MODE", raising=False)
    assert resolve_mode({"registry": {"mode": "distributed"}}) == "distributed"


def test_resolve_mode_env_overrides_config(monkeypatch):
    monkeypatch.setenv("MCP_REGISTRY_MODE", "distributed")
    # Config says embedded, env wins.
    assert resolve_mode({"registry": {"mode": "embedded"}}) == "distributed"


def test_create_app_honors_mode_env_override(monkeypatch):
    from device_mcp_gateway.main import create_app

    monkeypatch.setenv("MCP_REGISTRY_MODE", "distributed")
    monkeypatch.delenv("MCP_SECRET_KEY", raising=False)
    # Config file says embedded; env forces distributed. With plaintext allowed
    # the app builds and reports the overridden mode.
    cfg = {"registry": {"mode": "embedded"}, "gateway": {"allow_plaintext_credentials": True}}
    app = create_app(override_config=cfg)
    assert app.state.mode == "distributed"
