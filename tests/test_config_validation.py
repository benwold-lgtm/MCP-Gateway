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


def test_multi_issuer_oidc_config_validates_clean():
    """A config that actually ENABLES OIDC must validate (ADR-0013 §6/§6a).

    Regression: `gateway.oidc` and `gateway.tenant_id` were absent from the schema, so a
    working multi-issuer deployment was warned at startup that its OIDC block was an
    unknown key and "ignored" — the opposite of true, and an operator following the
    warning would delete working config. It survived the suite because every OIDC key in
    the shipped `config.yaml` is commented out, so `test_shipped_config_yaml_validates_clean`
    never exercised one. Found by pointing a real gateway at two real IdP realms.
    """
    cfg = {
        "gateway": {
            "tenant_id": "acme",
            "oidc": {
                "enabled": True,
                "issuers": [
                    {
                        "issuer": "https://login.example.com/realms/corp",
                        "audience": "mcp-gateway",
                        "plane": "tenant",
                        "group_roles": {"mcp-admins": "admin"},
                    },
                    {
                        "issuer": "https://provider-idp.example.com",
                        "audience": "mcp-gateway",
                        "plane": "provider",
                        "group_roles": {"mcp-admins": "operator"},
                        "step_up_acr": ["urn:example:step-up"],
                        "grant_claim": "mcp_grant",
                    },
                ],
            },
        }
    }
    assert validate_config(cfg) == []


def test_oidc_typo_is_still_flagged():
    # Declaring `oidc` opaque must not turn its neighbours into a blind spot.
    problems = validate_config({"gateway": {"oidcc": {}}})
    assert any("gateway.oidcc" in p for p in problems)


def test_tenant_id_type_is_checked():
    problems = validate_config({"gateway": {"tenant_id": 5}})
    assert any("gateway.tenant_id" in p and "str" in p for p in problems)


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


def test_bind_host_env_override_suppresses_false_bind_all_warning(monkeypatch):
    # `device-mcp --host 127.0.0.1` over a 0.0.0.0 config exports MCP_BIND_HOST; the
    # warning must reflect the effective bind, not the config value (no false positive).
    monkeypatch.setenv("MCP_BIND_HOST", "127.0.0.1")
    cfg = {"server": {"host": "0.0.0.0"}}
    warnings = warn_unsafe_settings(cfg, "embedded", auth_enabled=False)
    assert not any("all interfaces" in w for w in warnings)


def test_bind_host_env_override_can_surface_bind_all_warning(monkeypatch):
    # Conversely, --host 0.0.0.0 over a loopback config must still warn (no auth).
    monkeypatch.setenv("MCP_BIND_HOST", "0.0.0.0")
    cfg = {"server": {"host": "127.0.0.1"}}
    warnings = warn_unsafe_settings(cfg, "embedded", auth_enabled=False)
    assert any("all interfaces" in w for w in warnings)


def test_warns_when_mtls_verify_disabled():
    # Disabling outbound cert verification is a fleet-wide MITM foot-gun (R1).
    cfg = {"server": {"host": "127.0.0.1"}, "security": {"mtls": {"verify": False}}}
    warnings = warn_unsafe_settings(cfg, "distributed", auth_enabled=True)
    assert any("mtls.verify" in w for w in warnings)


def test_no_mtls_warning_when_verify_true():
    cfg = {"server": {"host": "127.0.0.1"}, "security": {"mtls": {"verify": True, "ca_bundle": "/x"}}}
    warnings = warn_unsafe_settings(cfg, "distributed", auth_enabled=True)
    assert not any("mtls.verify" in w for w in warnings)
