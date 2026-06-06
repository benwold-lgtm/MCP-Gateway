# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Configuration loader — reads and returns the central config.yaml."""

import os
from typing import Any

import yaml
from loguru import logger

CONFIG_PATH = os.getenv("MCP_CONFIG", "config.yaml")


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
    return data


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
