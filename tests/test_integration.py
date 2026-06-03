"""
Integration Test: Register Mock OpenAPI Device -> Verify Gateway Health & Metrics
"""

import json
import time


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

    client_id = "test-sse-client"
    with client.stream("GET", f"/devices/{hostname}/sse?client_id={client_id}") as event_resp:
        assert event_resp.status_code == 200

        send_resp = client.post(
            f"/devices/{hostname}/messages?client_id={client_id}",
            json={"tool": "get_device_status", "arguments": {}},
        )
        assert send_resp.status_code == 200
        assert send_resp.json().get("status") == "sent"

        data_line = None
        event_name = None
        data_payload = ""
        deadline = time.time() + 10
        for line in event_resp.iter_lines():
            if time.time() > deadline:
                break
            if line is None:
                continue
            line = line.strip()
            if line == "":
                if event_name == "message" and data_payload:
                    data_line = data_payload
                    break
                event_name = None
                data_payload = ""
                continue

            if line.startswith("event:"):
                event_name = line[len("event:") :].strip()
                continue
            if line.startswith("data:"):
                data_payload += line[len("data:") :].strip()
                continue

        assert data_line is not None, "No SSE message event received"
        payload = json.loads(data_line)
        assert "result" in payload, f"Expected 'result' key in SSE payload, got: {payload}"
        assert payload["result"]["body"]["status"] == "online"

    del_resp = client.delete(f"/devices/{hostname}")
    assert del_resp.status_code == 200
    print("[PASS] SSE transport client flow verified.")


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
