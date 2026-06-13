# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
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
    audit_file: str = "logs/audit.log",
    audit_retention: str = "90 days",
    audit_enabled: bool = True,
) -> None:
    """Configure loguru sinks.

    stderr sink: human-readable colored format (dev consoles, kubectl logs).
    file sink: newline-delimited JSON when json_logs=True (Splunk UF, Fluent Bit, Promtail),
               plain text otherwise.
    audit sink: a dedicated, always-JSON, hash-chained stream of ``event="audit"`` records
               (F-57), kept on a time-based retention (F-58). This is the clean stream to
               forward to a SIEM / WORM store; tamper-evidence is verifiable offline with
               ``device_mcp_gateway.audit.verify_audit_chain`` (or ``-m
               device_mcp_gateway.audit_verify``).

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

    # Dedicated audit sink (F-57/F-58) — only event="audit" records, always JSON,
    # on a time-based retention. Continue the tamper-evident hash chain from the
    # existing file so a restart isn't mistaken for a deleted record.
    if audit_enabled:
        audit_dir = os.path.dirname(audit_file)
        if audit_dir:
            os.makedirs(audit_dir, exist_ok=True)
        from device_mcp_gateway.audit import init_audit_chain

        init_audit_chain(audit_file)
        logger.add(
            audit_file,
            level="INFO",
            rotation=f"{max_size_mb} MB",
            retention=audit_retention,  # time-based, e.g. "90 days" (F-58)
            serialize=True,
            filter=lambda rec: rec["extra"].get("event") == "audit",
            enqueue=True,  # don't let audit I/O block the request path
        )

    logger.info(
        f"Logging initialized (level={level}, json_logs={json_logs}, file={log_file}, "
        f"audit_file={audit_file if audit_enabled else 'disabled'}, audit_retention={audit_retention})"
    )
