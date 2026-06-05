# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""
CLI entry point for the Device MCP Gateway.

Usage:
    device-mcp [--config PATH] [--host HOST] [--port PORT] [--log-level LEVEL]
"""

import argparse
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="device-mcp",
        description="Device MCP Gateway — serve OpenAPI devices as MCP tool servers",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=os.getenv("MCP_CONFIG", "config.yaml"),
        help="Path to config.yaml (default: $MCP_CONFIG or ./config.yaml)",
    )
    parser.add_argument("--host", metavar="HOST", help="Bind address (overrides config)")
    parser.add_argument("--port", metavar="PORT", type=int, help="Port (overrides config)")
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity (overrides config)",
    )
    args = parser.parse_args()

    # Set before importing the app so load_config() picks it up.
    os.environ["MCP_CONFIG"] = args.config

    if not os.path.exists(args.config):
        print(f"Warning: config file '{args.config}' not found — using built-in defaults", file=sys.stderr)

    try:
        import uvicorn
        from device_mcp_gateway.cfg import load_config

        cfg = load_config(args.config)
        host = args.host or cfg.get("server", {}).get("host", "0.0.0.0")
        port = args.port or cfg.get("server", {}).get("port", 8000)
        log_level = (args.log_level or cfg.get("logging", {}).get("level", "INFO")).lower()

        uvicorn.run(
            "device_mcp_gateway.main:app",
            host=host,
            port=port,
            log_level=log_level,
        )
    except ImportError as exc:
        print(f"Error: missing dependency — {exc}", file=sys.stderr)
        print("Run: pip install -e .", file=sys.stderr)
        sys.exit(1)


def worker_main() -> None:
    """Entry point for the device-mcp-worker process (distributed mode)."""
    import asyncio
    import os
    import socket

    parser = argparse.ArgumentParser(
        prog="device-mcp-worker",
        description="Device MCP Worker — runs DevicePods for distributed mode",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=os.getenv("MCP_CONFIG", "config.yaml"),
        help="Path to config.yaml (default: $MCP_CONFIG or ./config.yaml)",
    )
    parser.add_argument(
        "--worker-id",
        metavar="ID",
        default=os.getenv("WORKER_ID", socket.gethostname()),
        help="Unique worker identifier (default: $WORKER_ID or hostname)",
    )
    args = parser.parse_args()
    os.environ["MCP_CONFIG"] = args.config

    try:
        from device_mcp_gateway.cfg import load_config
        from device_mcp_gateway.shared.redis_client import create_redis
        from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
        from device_mcp_gateway.worker.runner import DeviceWorker
        from device_mcp_gateway.logging_setup import setup_logging

        cfg = load_config(args.config)
        log_cfg = cfg.get("logging", {})
        setup_logging(
            level=log_cfg.get("level", "INFO"),
            log_file=log_cfg.get("file", "logs/worker.log"),
            max_size_mb=log_cfg.get("max_size", 50),
            backup_count=log_cfg.get("backup_count", 5),
        )

        secret_raw: str = os.getenv("MCP_SECRET_KEY") or cfg.get("gateway", {}).get("secret_key") or ""
        fernet = None
        if secret_raw:
            try:
                from cryptography.fernet import Fernet

                fernet = Fernet(secret_raw.encode() if isinstance(secret_raw, str) else secret_raw)
            except Exception as exc:
                import sys

                print(f"Warning: invalid MCP_SECRET_KEY — credentials will not be decryptable: {exc}", file=sys.stderr)

        async def _run() -> None:
            redis_client = await create_redis(cfg)
            backend = RedisRegistryBackend(redis_client)
            worker = DeviceWorker(
                worker_id=args.worker_id,
                config=cfg,
                redis_client=redis_client,
                fernet=fernet,
            )
            await worker.run(backend)

        asyncio.run(_run())
    except ImportError as exc:
        import sys

        print(f"Error: missing dependency — {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
