"""
Structured logging setup for the gateway.
"""

import os
import sys
from loguru import logger

def setup_logging(level: str = "INFO", log_file: str = "logs/gateway.log"):
    """Configure loguru with rotation and structured output."""
    logger.remove()
    logger.add(sys.stderr, level=level, format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logger.add(log_file, rotation="50 MB", retention="5 days", level=level)
    logger.info("Logging initialized")
