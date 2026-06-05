"""
Integration Test: Register Mock OpenAPI Device -> Verify Gateway Health & Metrics
"""

import json
import time
from unittest.mock import AsyncMock

import pytest


def test_register_and_metrics(client, mock_target_url):
    """
    1. POST /devices to register mock endpoint.
    2. Verify GET /devices shows the registered device as reachable.
    3. Verify GET /metrics reports correct counts.
    4. Verify GET /health returns healthy status.
    """
    # 1. Register device pointing to our mock API
    reg_payload = {"hostname": "mock-iot.local", "base_url": mock_target_url, "auth_type": "none", "transport": "sse"}
    reg_resp = client.post("/devices", json=reg_payload)
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.json()}"
    reg_data = reg_resp.json()
    assert reg_data["hostname"] == "mock-iot.local"
    assert "pod_active" in reg_data
    assert "reachable" in reg_data
    assert "spawn_error" in reg_data
    print("[+] Device registered via /devices endpoint")

    # 2. Verify device appears in the list and is reachable
    dev_resp = client.get("/devices")
    assert dev_resp.status_code == 200
    devices = dev_resp.json().get("devices", [])
    mock_dev = next((d for d in devices if d["hostname"] == "mock-iot.local"), None)
    assert mock_dev is not None, "Device not found in /devices list"
    assert mock_dev.get("reachable") is True, "Mock API should be reachable"
    print(f"[+] Device status verified: {mock_dev}")

    # 3. Verify metrics endpoint returns correct counts
    met_resp = client.get("/metrics")
    assert met_resp.status_code == 200
    metrics = met_resp.json()
    assert metrics.get("total_registered", 0) >= 1, f"Total registered mismatch: {metrics}"
    assert metrics.get("reachable_devices", 0) >= 1, f"Reachable mismatch: {metrics}"
    assert metrics.get("unreachable_devices", 0) == 0, f"Unreachable mismatch: {metrics}"
    print(f"[+] Metrics verified: {metrics}")

    # 4. Verify /health endpoint
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    health = health_resp.json()
    assert health.get("status") == "healthy", f"Health status unexpected: {health}"
    assert health.get("registered_devices", 0) >= 1, f"Health devices count mismatch: {health}"
    print(f"[+] Health endpoint verified: {health}")

    # 5. Verify deregistration works
    del_resp = client.delete("/devices/mock-iot.local")
    assert del_resp.status_code == 200, f"Deregistration failed: {del_resp.json()}"
    print("[+] Device deregistered successfully")

    # Verify it's gone
    dev_resp2 = client.get("/devices")
    devices2 = dev_resp2.json().get("devices", [])
    remaining = [d for d in devices2 if d["hostname"] == "mock-iot.local"]
    assert len(remaining) == 0, "Device should be removed from list"
    print("[+] Device removal verified")

    print("[PASS] Full integration test passed.")


def test_sse_transport_client_flow(client, mock_target_url):
    hostname = "mock-iot-sse.local"
    reg_payload = {
        "hostname": hostname,
        "base_url": mock_target_url,
        "auth_type": "none",
        "transport": "sse",
    }
    reg_resp = client.post("/devices", json=reg_payload)
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.json()}"

    start = time.time()
    while time.time() - start < 5:
        dev_resp = client.get("/devices")
        assert dev_resp.status_code == 200
        devices = dev_resp.json().get("devices", [])
        mock_dev = next((d for d in devices if d["hostname"] == hostname), None)
        if mock_dev and mock_dev.get("pod_active"):
            break
        time.sleep(0.2)
    else:
        raise AssertionError("SSE device pod did not become active")

    with client.stream("GET", f"/devices/{hostname}/sse") as event_resp:
        assert event_resp.status_code == 200

        # Single-pass iterator: read endpoint event first (server-assigned session_id),
        # then POST the tool call inside the loop, then read the message event.
        # Two separate iter_lines() calls would raise StreamConsumed on the same stream.
        session_id = None
        data_line = None
        event_name = None
        data_payload = ""
        _posted = False
        deadline = time.time() + 15

        for line in event_resp.iter_lines():
            if time.time() > deadline:
                break
            if line is None:
                continue
            line = line.strip()
            if line == "":
                if event_name == "endpoint" and data_payload and "session_id=" in data_payload:
                    session_id = data_payload.split("session_id=")[-1]
                    send_resp = client.post(
                        f"/devices/{hostname}/messages?session_id={session_id}",
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": "get_device_status", "arguments": {}},
                        },
                    )
                    assert send_resp.status_code == 200
                    assert send_resp.json().get("status") == "accepted"
                    _posted = True
                elif event_name == "message" and data_payload and _posted:
                    data_line = data_payload
                    break
                event_name = None
                data_payload = ""
                continue
            if line.startswith("event:"):
                event_name = line[len("event:"):].strip()
                continue
            if line.startswith("data:"):
                data_payload += line[len("data:"):].strip()
                continue

        assert data_line is not None, "No SSE message event received"
        rpc_response = json.loads(data_line)
        assert "result" in rpc_response, f"Expected JSON-RPC result in SSE payload, got: {rpc_response}"
        assert rpc_response["jsonrpc"] == "2.0"
        assert rpc_response["id"] == 1
        content = rpc_response["result"]["content"]
        assert len(content) > 0, "Expected non-empty content in tools/call result"
        tool_result = json.loads(content[0]["text"])
        assert tool_result["body"]["status"] == "online"

    del_resp = client.delete(f"/devices/{hostname}")
    assert del_resp.status_code == 200
    print("[PASS] SSE transport client flow verified.")


@pytest.mark.asyncio
async def test_spec_change_replaces_pod():
    """When a device's OpenAPI spec hash changes, the running pod is torn down and replaced."""
    from device_mcp_gateway.registry.server import Registry

    spec_v1 = {
        "openapi": "3.0.3",
        "info": {"title": "Sensor API", "version": "1.0.0"},
        "paths": {
            "/status": {"get": {"operationId": "get_status", "responses": {"200": {"description": "OK"}}}}
        },
    }
    spec_v2 = {
        "openapi": "3.0.3",
        "info": {"title": "Sensor API", "version": "2.0.0"},
        "paths": {
            "/status": {"get": {"operationId": "get_status", "responses": {"200": {"description": "OK"}}}},
            "/health": {"get": {"operationId": "check_health", "responses": {"200": {"description": "OK"}}}},
        },
    }

    registry = Registry(config={"spec_cache_ttl": 10, "health_check_interval": 10, "max_concurrent_pods": 10})
    registry.check_reachability = AsyncMock(return_value=True)
    registry._discover_spec = AsyncMock(return_value=spec_v1)

    device_cfg = await registry.register_device(hostname="spec-change-test", base_url="http://test.local")
    assert device_cfg.pod_active, "Pod should be active after initial registration"

    # Get the embedded-mode DeviceProfile (has pod reference and spec_data)
    profile = registry.get_profile("spec-change-test")
    assert profile is not None
    initial_pod = profile.pod
    assert len(profile.pod.manifest.tools) == 1, "Initial pod should have 1 tool"

    # Simulate upstream spec update
    registry._discover_spec = AsyncMock(return_value=spec_v2)
    registry._spec_cache._store.clear()
    profile.config.last_check = 0.0  # force cache miss so fetch_spec re-fetches

    await registry.fetch_spec(profile)

    profile = registry.get_profile("spec-change-test")  # re-fetch after pod replacement
    assert profile.pod_active, "Pod should still be active after spec change"
    assert profile.pod is not initial_pod, "A new pod should have been spawned"
    assert len(profile.pod.manifest.tools) == 2, "New pod should expose 2 tools from spec v2"

    await registry.shutdown()
    print("[PASS] Spec change pod replacement verified.")


def test_register_unreachable_device_reports_failure(client):
    """Registering an unreachable device should still return 200 but surface pod_active=False."""
    hostname = "unreachable-device.local"
    resp = client.post(
        "/devices",
        json={
            "hostname": hostname,
            "base_url": "http://192.0.2.1",  # TEST-NET, guaranteed unreachable
            "auth_type": "none",
            "transport": "sse",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["hostname"] == hostname
    assert data["pod_active"] is False
    assert data["reachable"] is False

    # Clean up
    client.delete(f"/devices/{hostname}")
    print("[PASS] Unreachable device registration feedback verified.")
