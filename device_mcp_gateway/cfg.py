# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Configuration loader — reads and returns the central config.yaml."""

import os
from typing import Any

import yaml
from loguru import logger

CONFIG_PATH = os.getenv("MCP_CONFIG", "config.yaml")

# Numeric leaf — accept int or float, but not bool (bool is a subclass of int).
_NUM = (int, float)

# Declared config schema (F-50): the set of known sections/keys and their expected
# value types. A leaf is a Python type (or tuple of types); a nested dict is a
# sub-section that is recursed into. This is the source of truth used to catch the
# silent-typo footgun — a misspelled or misplaced key is read with a .get() default
# elsewhere and otherwise ignored without warning.
_CONFIG_SCHEMA: dict[str, Any] = {
    "gateway": {
        "api_key": str,
        "allow_anonymous": bool,
        "rbac": list,
        "secret_key": str,
        "allow_plaintext_credentials": bool,
        "max_body_bytes": int,
        "read_cache_ttl": _NUM,
        "trust_proxy_headers": bool,
    },
    "server": {"host": str, "port": int},
    "registry": {
        "mode": str,
        "health_check_interval": _NUM,
        "spec_poll_interval": _NUM,
        "spec_cache_ttl": _NUM,
        "tool_call_timeout": _NUM,
        "registration_provision_budget": _NUM,
        "reconcile_interval": _NUM,
        "max_concurrent_calls_per_device": int,
        "rebalance_enabled": bool,
        "idempotency_guard": bool,
        "call_backlog_limit": int,
        "spec_max_bytes": int,
        "spec_translate_timeout": _NUM,
        "shutdown_drain_timeout": _NUM,
        "health_lock_ttl": _NUM,
        "max_concurrent_pods": int,
        "max_retries": int,
        "retry_base_delay": _NUM,
        "retry_max_delay": _NUM,
    },
    "redis": {
        "url": str,
        "allow_insecure": bool,
        "socket_timeout": _NUM,
        "max_connections": int,
        "pubsub_max_connections": int,
    },
    "auth": {
        "type": str,
        "api_key": {"header_name": str},
        "oauth2": {
            "token_endpoint": str,
            "client_id": str,
            "client_secret": str,
            "scopes": list,
        },
    },
    "transport": {"default": str, "sse": {"keep_alive_interval": _NUM}},
    "discovery": {"spec_paths": list, "timeout": _NUM},
    "storage": {"type": str, "db_path": str},
    "cors": {"allowed_origins": list},
    "security": {"allow_private_targets": bool},
    "metrics": {"enabled": bool, "port": int, "gauge_refresh_interval": _NUM},
    "tracing": {
        "enabled": bool,
        "otlp_endpoint": str,
        "service_name": str,
        "sample_ratio": _NUM,
    },
    "logging": {
        "level": str,
        "file": str,
        "max_size": _NUM,
        "backup_count": int,
        "json_logs": bool,
    },
}


def load_config(path: str = CONFIG_PATH) -> dict[str, Any]:
    """Load configuration from a YAML file.

    Missing or empty file → built-in defaults. Malformed YAML fails fast with a
    clear error rather than crashing later on a None/partial config.
    """
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Config file {path} not found, using defaults")
        return _defaults()
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Config file {path} is not valid YAML: {exc}") from exc

    if data is None:
        logger.warning(f"Config file {path} is empty, using defaults")
        return _defaults()
    if not isinstance(data, dict):
        raise RuntimeError(
            f"Config file {path} must contain a YAML mapping at the top level, got {type(data).__name__}"
        )
    validate_config(data, source=path)
    return data


def _type_ok(value: Any, expected: Any) -> bool:
    """Type check that treats bool as distinct from int/float (it's a subclass)."""
    if expected is bool:
        return isinstance(value, bool)
    types = expected if isinstance(expected, tuple) else (expected,)
    if isinstance(value, bool):
        # A bool is never a valid int/float/str leaf here — flag it as a mismatch.
        return bool in types
    return isinstance(value, types)


def _type_names(expected: Any) -> str:
    types = expected if isinstance(expected, tuple) else (expected,)
    return "/".join(t.__name__ for t in types)


def _validate_section(data: dict, schema: dict, prefix: str, problems: list[str]) -> None:
    """Recursively compare a config section against the schema, recording problems."""
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if key not in schema:
            problems.append(f"unknown config key '{dotted}' — ignored (typo? wrong section?)")
            continue
        expected = schema[key]
        if isinstance(expected, dict):
            if isinstance(value, dict):
                _validate_section(value, expected, f"{dotted}.", problems)
            else:
                problems.append(f"config key '{dotted}' should be a mapping, got {type(value).__name__}")
            continue
        # A leaf: None is allowed (means "unset / use default").
        if value is not None and not _type_ok(value, expected):
            problems.append(f"config key '{dotted}' should be {_type_names(expected)}, got {type(value).__name__}")


def validate_config(cfg: dict[str, Any], *, source: str = "config") -> list[str]:
    """Validate a loaded config against the declared schema (F-50).

    Surfaces the silent-typo footgun: unknown/misplaced keys and type mismatches are
    logged as warnings (with their dotted path) instead of being read-with-a-default
    and ignored. Returns the list of problem strings (also for testing). Warns rather
    than hard-fails so an otherwise-working deployment isn't taken down by a stray key.
    """
    problems: list[str] = []
    _validate_section(cfg, _CONFIG_SCHEMA, "", problems)
    for p in problems:
        logger.warning(f"Config validation ({source}): {p}")
    return problems


def warn_unsafe_settings(cfg: dict[str, Any], mode: str, auth_enabled: bool) -> list[str]:
    """Warn loudly when the *forgotten/default* posture is permissive (F-53).

    The safe path should be the default; these warnings make the convenient-but-unsafe
    states visible at startup instead of silent. Non-fatal (the hard refusals live in
    the Tier-0 distributed-mode gates); returns the warning strings for testing.
    """
    warnings: list[str] = []
    host = cfg.get("server", {}).get("host", "0.0.0.0")  # nosec B104 — default fallback for a read, not a bind
    origins = cfg.get("cors", {}).get("allowed_origins", []) or []

    if not auth_enabled:
        warnings.append(
            "authentication is DISABLED — every API request is served with full access. "
            "Set gateway.api_key / MCP_ADMIN_KEY / gateway.rbac to require a token."
        )
    if "*" in origins:
        warnings.append(
            "cors.allowed_origins contains '*' (wildcard) while credentials are allowed — any origin "
            "can call the API from a browser. Set explicit origins for anything but local development."
        )
    if host in ("0.0.0.0", "::") and not auth_enabled:  # nosec B104 — detecting bind-all to warn, not binding
        warnings.append(
            f"binding {host} (all interfaces) with authentication disabled — the API is reachable and "
            "unauthenticated on every network interface. Bind 127.0.0.1 or enable auth."
        )
    for w in warnings:
        logger.warning(f"Unsafe configuration ({mode} mode): {w}")
    return warnings


def resolve_mode(cfg: dict[str, Any]) -> str:
    """Resolve registry mode, letting MCP_REGISTRY_MODE override the config file.

    Centralised so the gateway and worker agree on the mode and can't silently
    diverge (gateway embedded + worker distributed = split brain).
    """
    return os.getenv("MCP_REGISTRY_MODE") or cfg.get("registry", {}).get("mode", "embedded")


def _defaults() -> dict:
    return {
        "gateway": {
            "api_key": "",
            "secret_key": "",
            "allow_plaintext_credentials": False,
            "max_body_bytes": 1_048_576,
        },
        "server": {"host": "0.0.0.0", "port": 8000},  # nosec B104 — bind-all is intended in containers
        "registry": {
            "mode": "embedded",
            "health_check_interval": 30,
            "spec_poll_interval": 300,
            "spec_cache_ttl": 3600,
            "tool_call_timeout": 30,
            "max_concurrent_pods": 50,
            "max_retries": 2,
            "retry_base_delay": 0.2,
            "retry_max_delay": 5.0,
        },
        "redis": {
            "url": "redis://localhost:6379/0",
            "socket_timeout": 5,
            "max_connections": 20,
            "pubsub_max_connections": 1000,
        },
        "auth": {"type": "api_key"},
        "transport": {"default": "sse"},
        "storage": {"db_path": "./data/devices.db"},
        "cors": {"allowed_origins": []},
        "metrics": {"enabled": True, "port": 9100, "gauge_refresh_interval": 15},
        "logging": {"level": "INFO"},
    }
