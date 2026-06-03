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
        from device_mcp_gateway.cfg.settings import load_config

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


if __name__ == "__main__":
    main()
