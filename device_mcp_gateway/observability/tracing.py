# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Optional OpenTelemetry tracing (F-14).

Distributed tracing across the gateway → Redis → worker → upstream hop, so a tool
call is one trace end to end and latency attribution stops being manual. The
gateway's request id (``rid``) is attached as a span attribute, tying spans back
to the existing log/audit correlation.

Two hard rules so this never destabilises a deployment:

  * **No-op unless opted in.** Tracing is off until ``tracing.enabled: true`` *and*
    the ``opentelemetry`` packages are installed (``pip install '.[otel]'``). When
    off, every function here is a cheap no-op — importing this module never fails,
    and disabled spans add no measurable latency.
  * **Never raises.** Setup failures (bad endpoint, missing exporter) downgrade to
    disabled with a warning rather than propagating.

Context crosses the Redis hop as a W3C ``traceparent`` string carried in the
call-stream fields: the gateway injects the current span context before XADD; the
worker extracts it and starts the execution span as a child.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from loguru import logger

_TRACER: Any = None  # set to an OTel Tracer when active; None ⇒ disabled
_PROPAGATOR: Any = None  # W3C TraceContext propagator when active


def tracing_enabled() -> bool:
    """True only when a tracer is configured and active."""
    return _TRACER is not None


def init_tracing(cfg: dict | None, service_name: str) -> bool:
    """Configure the global tracer from config; return whether tracing is active.

    Idempotent and safe to call once at gateway/worker startup. Returns False
    (staying no-op) when disabled, when the optional dependency is missing, or on
    any setup error — always logging the reason.
    """
    global _TRACER, _PROPAGATOR
    if _TRACER is not None:
        return True  # already initialised

    tcfg = (cfg or {}).get("tracing", {}) if cfg else {}
    if not tcfg.get("enabled", False):
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    except ImportError:
        logger.warning(
            "tracing.enabled is true but the OpenTelemetry packages are not installed; "
            "tracing stays OFF. Install with: pip install '.[otel]'"
        )
        return False

    try:
        sample_ratio = float(tcfg.get("sample_ratio", 1.0))
        endpoint = tcfg.get("otlp_endpoint", "http://localhost:4318/v1/traces")
        name = tcfg.get("service_name", service_name)
        provider = TracerProvider(
            resource=Resource.create({"service.name": name}),
            sampler=TraceIdRatioBased(sample_ratio),
        )
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        _TRACER = trace.get_tracer("device_mcp_gateway")
        _PROPAGATOR = TraceContextTextMapPropagator()
        logger.info(f"OpenTelemetry tracing enabled (service={name}, endpoint={endpoint}, sample={sample_ratio})")
        return True
    except Exception as exc:  # pragma: no cover - defensive: never let setup crash startup
        logger.warning(f"Failed to initialise tracing; staying OFF: {exc}")
        _TRACER = None
        _PROPAGATOR = None
        return False


@contextmanager
def start_span(name: str, *, attributes: dict | None = None) -> Iterator[Any]:
    """Start a span for ``name``; a no-op context manager when tracing is off."""
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as span:
        _apply_attributes(span, attributes)
        yield span


@contextmanager
def start_span_from_carrier(name: str, carrier: dict | None, *, attributes: dict | None = None) -> Iterator[Any]:
    """Start ``name`` as a child of the trace context extracted from ``carrier``.

    Used on the worker side: ``carrier`` holds the ``traceparent`` the gateway
    injected into the call-stream entry, so the worker's execution span joins the
    same trace. No-op when tracing is off.
    """
    if _TRACER is None or _PROPAGATOR is None:
        yield None
        return
    ctx = _PROPAGATOR.extract(carrier or {})
    with _TRACER.start_as_current_span(name, context=ctx) as span:
        _apply_attributes(span, attributes)
        yield span


def inject_carrier(carrier: dict | None = None) -> dict:
    """Return ``carrier`` with the current span's ``traceparent`` injected.

    The single point of cross-process propagation. Returns the carrier unchanged
    (no ``traceparent`` added) when tracing is off, so callers can always pass the
    result through to the transport.
    """
    carrier = {} if carrier is None else carrier
    if _PROPAGATOR is not None:
        _PROPAGATOR.inject(carrier)
    return carrier


def _apply_attributes(span: Any, attributes: dict | None) -> None:
    if span is None or not attributes:
        return
    try:
        for k, v in attributes.items():
            if v is not None:
                span.set_attribute(k, v)
    except Exception:  # pragma: no cover - attribute setting must never break a call
        pass


def _reset_for_tests() -> None:
    """Test hook: drop any configured tracer so a test can re-init cleanly."""
    global _TRACER, _PROPAGATOR
    _TRACER = None
    _PROPAGATOR = None
