# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for the config loader's robustness (S2 finding F11).

load_config crashed on malformed YAML and returned None for an empty file
(blowing up later on .get()); _defaults() was embedded-only. It now fails fast
on bad YAML, falls back to complete defaults for missing/empty files, and the
defaults cover both modes.
"""

import pytest

from device_mcp_gateway.cfg import load_config, _defaults


def test_missing_file_returns_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "nope.yaml"))
    assert cfg["server"]["port"] == 8000


def test_empty_file_returns_defaults_not_none(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    cfg = load_config(str(p))
    assert isinstance(cfg, dict)
    assert "registry" in cfg


def test_malformed_yaml_fails_fast(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("server: {host: 0.0.0.0\n  port: : :")  # invalid YAML
    with pytest.raises(RuntimeError, match="not valid YAML"):
        load_config(str(p))


def test_non_mapping_top_level_rejected(tmp_path):
    p = tmp_path / "list.yaml"
    p.write_text("- a\n- b\n")
    with pytest.raises(RuntimeError, match="mapping at the top level"):
        load_config(str(p))


def test_valid_file_is_returned_verbatim(tmp_path):
    p = tmp_path / "ok.yaml"
    p.write_text("server:\n  port: 1234\n")
    cfg = load_config(str(p))
    assert cfg["server"]["port"] == 1234


def test_defaults_cover_both_modes():
    d = _defaults()
    # Distributed-mode defaults must be present so a defaults-only run is usable.
    for section in ("gateway", "redis", "cors", "storage", "registry", "server"):
        assert section in d, f"defaults missing {section}"
    assert "pubsub_max_connections" in d["redis"]
