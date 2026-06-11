# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Async Redis connection factory."""

import os
from typing import Any
from urllib.parse import urlparse

from loguru import logger

import redis.asyncio as aioredis


def redis_url(cfg: dict[str, Any]) -> str:
    """Resolve the Redis URL (MCP_REDIS_URL env overrides cfg)."""
    return os.getenv("MCP_REDIS_URL") or cfg.get("redis", {}).get("url", "redis://localhost:6379/0")


def assert_redis_secure(cfg: dict[str, Any]) -> None:
    """Refuse to run distributed mode against an unauthenticated Redis (Tier-0 F-24).

    Redis is the entire distributed control plane (registry, assignment/call/result
    streams, claims, leader locks). With no AUTH, anything that reaches port 6379 can
    inject tool calls or read state, so we require the Redis URL to carry a password
    (``redis://:<pw>@host`` or ``rediss://...``). TLS (``rediss://``) is additionally
    recommended for in-transit protection — see docs/kubernetes-architecture.md.

    Override for a trusted local/dev network with ``redis.allow_insecure: true``.
    """
    parsed = urlparse(redis_url(cfg))
    if parsed.password:
        return  # AUTH present
    if cfg.get("redis", {}).get("allow_insecure", False):
        logger.warning(
            "Redis AUTH disabled (redis.allow_insecure=true) — the distributed control plane is "
            "UNAUTHENTICATED. Anyone who can reach Redis can inject tool calls or read state. Set a "
            "password in MCP_REDIS_URL (redis://:<pw>@host, ideally rediss:// for TLS) in production."
        )
        return
    raise RuntimeError(
        "Refusing to start in distributed mode against an unauthenticated Redis: the URL carries no "
        "password, so the shared control plane (registry, tool-call streams, claims) is open to anyone "
        "who can reach it. Set a password — MCP_REDIS_URL=redis://:<password>@host:6379/0 (or rediss:// "
        "for TLS) — or, for a trusted local network only, set redis.allow_insecure: true to override."
    )


async def create_redis(cfg: dict[str, Any], max_connections: int | None = None) -> aioredis.Redis:
    """Create and return a shared async Redis client from config.

    Reads cfg["redis"] for url, socket_timeout, and max_connections.
    The MCP_REDIS_URL env var overrides cfg["redis"]["url"].

    Pass max_connections to override the pool size — used for the dedicated
    pub/sub client, which needs one connection per open SSE stream and so must
    be sized well above the command pool.
    """
    redis_cfg = cfg.get("redis", {})
    url = redis_url(cfg)
    pool_size = max_connections if max_connections is not None else redis_cfg.get("max_connections", 20)
    return aioredis.from_url(
        url,
        socket_timeout=redis_cfg.get("socket_timeout", 5),
        max_connections=pool_size,
        decode_responses=True,
    )
