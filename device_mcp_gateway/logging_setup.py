"""Structured logging setup for the gateway."""

import os
import sys

from loguru import logger


def setup_logging(
    level: str = "INFO",
    log_file: str = "logs/gateway.log",
    max_size_mb: int = 50,
    backup_count: int = 5,
) -> None:
    """Configure loguru with rotation and structured output."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:HH:mm:ss}</green> | <level>{level}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
        ),
    )
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logger.add(log_file, rotation=f"{max_size_mb} MB", retention=backup_count, level=level)
    logger.info("Logging initialized")
