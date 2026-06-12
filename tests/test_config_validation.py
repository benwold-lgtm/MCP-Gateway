# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for config schema validation (F-50) and safe-default warnings (F-53)."""

import yaml

from device_mcp_gateway.cfg import (
    _defaults,
    load_config,
    validate_config,
    warn_unsafe_settings,
)

# --- F-50 schema validation --------------------------------------------------


def test_defaults_validate_clean():
    assert validate_config(_defaults()) == []


def test_shipped_config_yaml_validates_clean():
    # The repo's config.yaml must not drift from the schema (every key is known/typed).
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)
    assert validate_config(cfg) == []


def test_unknown_top_level_key_flagged():
    problems = validate_config({"gatewayy": {}})
    assert any("gatewayy" in p for p in problems)


def test_unknown_nested_key_flagged_with_dotted_path():
    # The canonical footgun: a misspelled key inside a real section.
    problems = validate_config({"registry": {"reconcile_intervall": 30}})
    assert any("registry.reconcile_intervall" in p for p in problems)
    assert len(problems) == 1


def test_type_mismatch_flagged():
    problems = validate_config({"server": {"port": "8000"}})
    assert any("server.port" in p and "int" in p for p in problems)


def test_bool_not_accepted_for_int_leaf():
    problems = validate_config({"gateway": {"max_body_bytes": True}})
    assert any("gateway.max_body_bytes" in p for p in problems)


def test_int_accepted_for_numeric_leaf():
    # socket_timeout accepts int or float; an int must not be flagged.
    assert validate_config({"redis": {"socket_timeout": 5}}) == []
    assert validate_config({"redis": {"socket_timeout": 5.0}}) == []


def test_section_expected_mapping_but_scalar():
    problems = validate_config({"auth": "api_key"})
    assert any("auth" in p and "mapping" in p for p in problems)


def test_none_leaf_allowed():
    # An explicitly-null value means "unset / use default" and must not be flagged.
    assert validate_config({"logging": {"file": None}}) == []


def test_load_config_validates(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(yaml.safe_dump({"registry": {"bogus_key": 1}}))
    data = load_config(str(cfg_file))
    # Loading still succeeds (warn, don't fail) and returns the raw data.
    assert data == {"registry": {"bogus_key": 1}}


# --- F-53 safe-default warnings ----------------------------------------------


def test_warns_when_auth_disabled():
    warnings = warn_unsafe_settings({"server": {"host": "127.0.0.1"}}, "embedded", auth_enabled=False)
    assert any("authentication is DISABLED" in w for w in warnings)


def test_warns_on_wildcard_cors():
    cfg = {"server": {"host": "127.0.0.1"}, "cors": {"allowed_origins": ["*"]}}
    warnings = warn_unsafe_settings(cfg, "embedded", auth_enabled=True)
    assert any("wildcard" in w for w in warnings)


def test_warns_on_bind_all_with_no_auth():
    cfg = {"server": {"host": "0.0.0.0"}}
    warnings = warn_unsafe_settings(cfg, "embedded", auth_enabled=False)
    assert any("all interfaces" in w for w in warnings)


def test_bind_all_alone_is_not_warned_when_auth_enabled():
    # Bind-all is normal in containers; only the bind-all + no-auth combo is dangerous.
    cfg = {"server": {"host": "0.0.0.0"}, "cors": {"allowed_origins": ["https://app.example.com"]}}
    assert warn_unsafe_settings(cfg, "distributed", auth_enabled=True) == []


def test_safe_config_yields_no_warnings():
    cfg = {"server": {"host": "127.0.0.1"}, "cors": {"allowed_origins": ["https://app.example.com"]}}
    assert warn_unsafe_settings(cfg, "embedded", auth_enabled=True) == []
