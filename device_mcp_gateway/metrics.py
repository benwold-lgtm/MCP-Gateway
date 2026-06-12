# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Prometheus metrics for the gateway and workers.

Exposition is served on a **dedicated metrics port** (default 9100), separate from
the public API port — so a `ServiceMonitor`/NetworkPolicy can target a named
`metrics` port without opening an unauthenticated hole in the API surface, and the
gateway and worker share one pattern. Run **one process per pod** (scale via
replicas) so the default global registry needs no multiprocess mode.

HTTP metrics are labelled with the **route template** (`/devices/{hostname}`), never
the concrete path — concrete paths are unbounded cardinality and will OOM Prometheus.
"""

import os

from loguru import logger
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from prometheus_client import start_http_server as _start_http_server

__all__ = [
    "CONTENT_TYPE_LATEST",
    "generate_latest",
    "http_requests_total",
    "http_request_duration_seconds",
    "tool_calls_total",
    "tool_call_duration_seconds",
    "registered_devices",
    "active_pods",
    "reachable_devices",
    "active_sse_connections",
    "worker_pods",
    "worker_pending_calls",
    "worker_assignments_lag",
    "worker_undelivered_calls",
    "tool_call_timeouts_total",
    "sse_messages_dropped_total",
    "dead_letter_total",
    "circuit_breaker_opens_total",
    "upstream_retries_total",
    "metrics_port",
    "metrics_enabled",
    "start_metrics_server",
    "route_template",
]

# --- Default port / enable, overridable by config or env ---------------------

_DEFAULT_PORT = 9100


def metrics_port(cfg: dict | None = None, default: int = _DEFAULT_PORT) -> int:
    """Resolve the metrics port: env MCP_METRICS_PORT > config metrics.port > default."""
    env = os.getenv("MCP_METRICS_PORT")
    if env:
        return int(env)
    if cfg:
        return int(cfg.get("metrics", {}).get("port", default))
    return default


def metrics_enabled(cfg: dict | None = None) -> bool:
    """Whether to start the exposition server. env MCP_METRICS_ENABLED > config > True."""
    env = os.getenv("MCP_METRICS_ENABLED")
    if env is not None:
        return env.lower() not in ("0", "false", "no")
    if cfg:
        return bool(cfg.get("metrics", {}).get("enabled", True))
    return True


# --- Instruments (registered on the process-global default REGISTRY) ---------

http_requests_total = Counter(
    "mcp_http_requests_total",
    "Total HTTP requests handled by the gateway.",
    ["method", "route", "status"],
)
http_request_duration_seconds = Histogram(
    "mcp_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    ["method", "route"],
)

# Tool-call metrics are incremented where calls *execute* (embedded gateway
# dispatch and the worker), not where they are merely enqueued.
tool_calls_total = Counter(
    "mcp_tool_calls_total",
    "Total MCP tool calls executed.",
    ["hostname", "method", "status"],
)
tool_call_duration_seconds = Histogram(
    "mcp_tool_call_duration_seconds",
    "MCP tool call execution duration in seconds.",
    ["hostname"],
)
# Bounded outbound retries on idempotent calls (F-05/F-44). `reason` is the trigger
# (e.g. status_503, status_429, TimeoutException) so retry storms are diagnosable.
upstream_retries_total = Counter(
    "mcp_upstream_retries_total",
    "Total outbound upstream call retries (idempotent ops only).",
    ["hostname", "reason"],
)

# Device-fleet gauges, refreshed by a periodic task (collection is sync; the
# registry read is async, so we cannot compute these inside a Prometheus collector).
registered_devices = Gauge("mcp_registered_devices", "Number of registered devices.")
active_pods = Gauge("mcp_active_pods", "Number of devices with an active pod.")
reachable_devices = Gauge("mcp_reachable_devices", "Number of reachable devices.")

# Per-replica live SSE connection count (Prometheus sums across replicas).
active_sse_connections = Gauge(
    "mcp_active_sse_connections",
    "Currently open SSE connections on this replica.",
)

# --- Worker-side gauges (distributed mode) -----------------------------------
# Per-worker, refreshed on a timer. Prometheus distinguishes workers by the
# scrape target (instance label), so these stay single-series per worker.
worker_pods = Gauge("mcp_worker_pods", "DevicePods currently running on this worker.")
worker_pending_calls = Gauge(
    "mcp_worker_pending_calls",
    "Delivered-but-unacked tool calls across this worker's device call streams. "
    "Primary signal for the worker HPA (Redis Stream consumer lag).",
)
worker_assignments_lag = Gauge(
    "mcp_worker_assignments_lag",
    "Pending entries in this worker's assignments consumer group.",
)
# Undelivered (never-read) tool-call backlog across this worker's device streams
# (XINFO GROUPS lag). worker_pending_calls counts delivered-but-unacked (in-flight)
# work; this counts work not yet read — held back by the per-device concurrency cap
# (SRE #5). Sum the two for total work waiting → the recommended worker HPA signal.
worker_undelivered_calls = Gauge(
    "mcp_worker_undelivered_calls",
    "Tool-call stream entries not yet delivered to this worker's consumer group "
    "(never-read backlog). Add to mcp_worker_pending_calls for total work waiting.",
)

# --- Failure-mode counters (SRE O1) ------------------------------------------
# Counters at the exact sites where requests fail or are shed, so failures are
# visible in Prometheus instead of only in logs.
tool_call_timeouts_total = Counter(
    "mcp_tool_call_timeouts_total",
    "Tool calls that hit the gateway's no-worker-responded timeout (F6).",
    ["hostname"],
)
sse_messages_dropped_total = Counter(
    "mcp_sse_messages_dropped_total",
    "SSE responses dropped because a client's queue was full (embedded mode).",
    ["hostname"],
)
dead_letter_total = Counter(
    "mcp_dead_letter_total",
    "Tool calls moved to a device's dead-letter stream because they were undeliverable.",
    ["hostname"],
)
circuit_breaker_opens_total = Counter(
    "mcp_circuit_breaker_opens_total",
    "Tool calls rejected because a device pod's circuit breaker was open.",
    ["hostname"],
)
calls_rejected_overload_total = Counter(
    "mcp_calls_rejected_overload_total",
    "Tool calls fast-failed with 429 because the device's call-stream backlog "
    "exceeded the admission watermark (F-06) — rejected up front instead of "
    "being silently trimmed at MAXLEN.",
    ["hostname"],
)


def start_metrics_server(port: int) -> bool:
    """Start the Prometheus exposition HTTP server on ``port``.

    Tolerant of "address already in use": the test suite builds many app
    instances in one process, and a metrics port collision must never crash the
    app or a test. Returns True if the server started, False otherwise.
    """
    try:
        _start_http_server(port)
        logger.info(f"Prometheus metrics server listening on :{port}")
        return True
    except OSError as exc:  # address in use, permission, etc. — non-fatal
        logger.warning(f"Metrics server not started on :{port}: {exc}")
        return False


def route_template(request) -> str:
    """Return the matched route's path template (e.g. ``/devices/{hostname}``).

    Starlette 1.2 does not expose ``scope["route"]`` — only ``scope["endpoint"]``
    after routing. We build (and cache on app.state) an endpoint→path_format map
    so labels stay low-cardinality. Unmatched requests (404 from scanners) collapse
    to ``__unmatched__`` so they cannot explode the label set.
    """
    endpoint = request.scope.get("endpoint")
    if endpoint is None:
        return "__unmatched__"
    app = request.scope.get("app")
    if app is None:
        return "__unmatched__"
    cache = getattr(app.state, "_metrics_route_cache", None)
    if cache is None:
        cache = {}
        for r in getattr(app.router, "routes", []):
            ep = getattr(r, "endpoint", None)
            path_format = getattr(r, "path_format", None) or getattr(r, "path", None)
            if ep is not None and path_format:
                cache[ep] = path_format
        app.state._metrics_route_cache = cache
    return cache.get(endpoint, "__unmatched__")
