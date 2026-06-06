# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Async Redis connection factory."""

import os
from typing import Any

import redis.asyncio as aioredis


async def create_redis(cfg: dict[str, Any], max_connections: int | None = None) -> aioredis.Redis:
    """Create and return a shared async Redis client from config.

    Reads cfg["redis"] for url, socket_timeout, and max_connections.
    The MCP_REDIS_URL env var overrides cfg["redis"]["url"].

    Pass max_connections to override the pool size — used for the dedicated
    pub/sub client, which needs one connection per open SSE stream and so must
    be sized well above the command pool.
    """
    redis_cfg = cfg.get("redis", {})
    url = os.getenv("MCP_REDIS_URL") or redis_cfg.get("url", "redis://localhost:6379/0")
    pool_size = max_connections if max_connections is not None else redis_cfg.get("max_connections", 20)
    return aioredis.from_url(
        url,
        socket_timeout=redis_cfg.get("socket_timeout", 5),
        max_connections=pool_size,
        decode_responses=True,
    )
