# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""F10 slice 1 — Prometheus metrics (gateway).

Covers the dedicated-port exposition helpers, route-template (low-cardinality)
labelling, the `/metrics/summary` rename, and the device-gauge refresher.
"""

import asyncio
import socket
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import device_mcp_gateway.main as gw_main
from device_mcp_gateway import metrics

client = TestClient(gw_main.app)


def _counter_value(counter, **labels) -> float:
    return counter.labels(**labels)._value.get()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- Port / enable resolution ------------------------------------------------


def test_metrics_port_precedence(monkeypatch):
    monkeypatch.delenv("MCP_METRICS_PORT", raising=False)
    assert metrics.metrics_port({"metrics": {"port": 9111}}) == 9111
    assert metrics.metrics_port(None) == 9100  # default
    monkeypatch.setenv("MCP_METRICS_PORT", "9222")
    assert metrics.metrics_port({"metrics": {"port": 9111}}) == 9222  # env wins


def test_metrics_enabled_precedence(monkeypatch):
    monkeypatch.delenv("MCP_METRICS_ENABLED", raising=False)
    assert metrics.metrics_enabled({"metrics": {"enabled": False}}) is False
    assert metrics.metrics_enabled(None) is True
    monkeypatch.setenv("MCP_METRICS_ENABLED", "0")
    assert metrics.metrics_enabled({"metrics": {"enabled": True}}) is False


# --- Exposition content ------------------------------------------------------


def test_exposition_contains_expected_metric_names():
    body = metrics.generate_latest().decode()
    for name in (
        "mcp_http_requests_total",
        "mcp_http_request_duration_seconds",
        "mcp_registered_devices",
        "mcp_active_pods",
        "mcp_reachable_devices",
        "mcp_active_sse_connections",
    ):
        assert name in body


# --- HTTP instrumentation: route-template labels -----------------------------


def test_request_counter_increments_with_route_template():
    before = _counter_value(metrics.http_requests_total, method="GET", route="/health", status="200")
    client.get("/health")
    after = _counter_value(metrics.http_requests_total, method="GET", route="/health", status="200")
    assert after == before + 1


def test_parametrised_route_uses_template_not_concrete_path():
    # Hits GET /devices/{hostname}; the endpoint runs (returns 404 for an unknown
    # device), so the label must be the *template*, never the concrete hostname.
    client.get("/devices/some-unknown-host-xyz")
    body = metrics.generate_latest().decode()
    assert 'route="/devices/{hostname}"' in body
    assert "some-unknown-host-xyz" not in body


def test_unmatched_path_collapses_to_sentinel():
    client.get("/no/such/path/at/all")
    body = metrics.generate_latest().decode()
    assert 'route="__unmatched__"' in body
    assert "/no/such/path/at/all" not in body


# --- /metrics/summary rename + auth ------------------------------------------


def test_old_metrics_path_is_gone():
    # The Prometheus exposition lives on the dedicated port now; the API-port
    # /metrics JSON endpoint was renamed to /metrics/summary.
    assert client.get("/metrics").status_code == 404


def test_metrics_summary_requires_auth(monkeypatch):
    monkeypatch.setattr(gw_main.app.state, "gateway_api_key", "secret-key")
    assert client.get("/metrics/summary").status_code == 401
    resp = client.get("/metrics/summary", headers={"Authorization": "Bearer secret-key"})
    assert resp.status_code == 200
    data = resp.json()
    assert "total_registered" in data
    assert "active_pods" in data


# --- Dedicated metrics server start ------------------------------------------


def test_start_metrics_server_on_free_port():
    assert metrics.start_metrics_server(_free_port()) is True


def test_start_metrics_server_tolerates_bound_port():
    # Occupy a port with a listening socket; the helper must return False, not raise.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert metrics.start_metrics_server(port) is False


# --- Gauge refresher ---------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_device_gauges_reflects_registry():
    devices = [
        SimpleNamespace(pod_active=True, reachable=True),
        SimpleNamespace(pod_active=True, reachable=False),
        SimpleNamespace(pod_active=False, reachable=False),
    ]

    class _Reg:
        async def list_devices(self):
            return devices

    app = SimpleNamespace(state=SimpleNamespace(registry=_Reg()))

    task = asyncio.create_task(gw_main._refresh_device_gauges(app, interval=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert metrics.registered_devices._value.get() == 3
    assert metrics.active_pods._value.get() == 2
    assert metrics.reachable_devices._value.get() == 1
