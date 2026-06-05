"""Structured logging setup for the gateway."""

import os
import sys

from loguru import logger


def setup_logging(
    level: str = "INFO",
    log_file: str = "logs/gateway.log",
    max_size_mb: int = 50,
    backup_count: int = 5,
    json_logs: bool = True,
) -> None:
    """Configure loguru sinks.

    stderr sink: human-readable colored format (dev consoles, kubectl logs).
    file sink: newline-delimited JSON when json_logs=True (Splunk UF, Fluent Bit, Promtail),
               plain text otherwise.

    With json_logs=True (the default), each log record is written to the file as a single
    JSON object per line. Fields added via logger.bind() appear under the top-level 'extra'
    key, which all major collectors (Splunk, Loki, Elastic) can index without custom
    extraction rules. See docs/observability.md for collector configuration examples.
    """
    logger.remove()

    # stderr — human-readable for interactive consoles and `kubectl logs`
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:HH:mm:ss}</green> | <level>{level}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
        ),
        colorize=True,
    )

    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # File sink — JSON for external collectors, plain text for local dev without a stack
    logger.add(
        log_file,
        rotation=f"{max_size_mb} MB",
        retention=backup_count,
        level=level,
        serialize=json_logs,  # serialize=True → newline-delimited JSON per record
    )

    logger.info(f"Logging initialized (level={level}, json_logs={json_logs}, file={log_file})")
