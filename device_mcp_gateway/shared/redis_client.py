# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Async Redis connection factory."""

import os
from typing import Any

import redis.asyncio as aioredis


async def create_redis(cfg: dict[str, Any]) -> aioredis.Redis:
    """Create and return a shared async Redis client from config.

    Reads cfg["redis"] for url, socket_timeout, and max_connections.
    The MCP_REDIS_URL env var overrides cfg["redis"]["url"].
    """
    redis_cfg = cfg.get("redis", {})
    url = os.getenv("MCP_REDIS_URL") or redis_cfg.get("url", "redis://localhost:6379/0")
    return aioredis.from_url(
        url,
        socket_timeout=redis_cfg.get("socket_timeout", 5),
        max_connections=redis_cfg.get("max_connections", 20),
        decode_responses=True,
    )
