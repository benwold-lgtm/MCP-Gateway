# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""LITE gateway first-run bootstrap: self-provisioned admin key via MCP_API_KEY_FILE."""

import stat

import pytest

from device_mcp_gateway.bootstrap import apply_gateway_bootstrap

_KEY_ENVS = ("MCP_API_KEY_FILE", "MCP_GATEWAY_API_KEY", "MCP_ADMIN_KEY", "MCP_VIEWER_KEY")


@pytest.fixture
def clean_env(monkeypatch):
    for k in _KEY_ENVS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_noop_without_key_file(clean_env):
    cfg = {"gateway": {}}
    apply_gateway_bootstrap(cfg)
    assert "api_key" not in cfg["gateway"]


def test_generates_persists_and_announces(clean_env, tmp_path, capsys):
    key_path = tmp_path / "gateway-api-key"
    clean_env.setenv("MCP_API_KEY_FILE", str(key_path))
    cfg = {"gateway": {}}

    apply_gateway_bootstrap(cfg)

    key = cfg["gateway"]["api_key"]
    assert key and key_path.read_text().strip() == key
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600  # not world-readable
    # Announced once so the operator can configure an MCP client.
    assert key in capsys.readouterr().err


def test_reuses_existing_key_file(clean_env, tmp_path, capsys):
    key_path = tmp_path / "gateway-api-key"
    key_path.write_text("preexisting-key\n")
    clean_env.setenv("MCP_API_KEY_FILE", str(key_path))
    cfg = {"gateway": {}}

    apply_gateway_bootstrap(cfg)

    assert cfg["gateway"]["api_key"] == "preexisting-key"
    # An existing key is not re-announced (it was surfaced on the run that made it).
    assert "preexisting-key" not in capsys.readouterr().err


def test_env_key_wins_no_generation(clean_env, tmp_path):
    key_path = tmp_path / "gateway-api-key"
    clean_env.setenv("MCP_API_KEY_FILE", str(key_path))
    clean_env.setenv("MCP_GATEWAY_API_KEY", "operator-key")
    cfg = {"gateway": {}}

    apply_gateway_bootstrap(cfg)

    # Operator-provided key is respected; nothing generated or written.
    assert "api_key" not in cfg["gateway"]
    assert not key_path.exists()


def test_config_key_wins_no_generation(clean_env, tmp_path):
    key_path = tmp_path / "gateway-api-key"
    clean_env.setenv("MCP_API_KEY_FILE", str(key_path))
    cfg = {"gateway": {"api_key": "from-config"}}

    apply_gateway_bootstrap(cfg)

    assert cfg["gateway"]["api_key"] == "from-config"
    assert not key_path.exists()
