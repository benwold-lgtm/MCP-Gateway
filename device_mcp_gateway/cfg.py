"""Configuration loader — reads and returns the central config.yaml."""

import os
from typing import Any

import yaml
from loguru import logger

CONFIG_PATH = os.getenv("MCP_CONFIG", "config.yaml")


def load_config(path: str = CONFIG_PATH) -> dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Config file {path} not found, using defaults")
        return _defaults()


def _defaults() -> dict:
    return {
        "server": {"host": "0.0.0.0", "port": 8000},
        "registry": {
            "health_check_interval": 30,
            "spec_poll_interval": 300,
            "spec_cache_ttl": 3600,
            "max_concurrent_pods": 50,
        },
        "auth": {"type": "api_key"},
        "transport": {"default": "sse"},
        "logging": {"level": "INFO"},
    }
