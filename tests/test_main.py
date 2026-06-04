import pytest

import device_mcp_gateway.main as gw_main
from fastapi.testclient import TestClient

client = TestClient(gw_main.app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "active_pods" in data
    assert "registered_devices" in data
    assert "version" in data


def test_health_does_not_require_auth(monkeypatch):
    monkeypatch.setattr(gw_main.app.state, "gateway_api_key", "test-secret")
    response = client.get("/health")
    assert response.status_code == 200


def test_auth_rejects_missing_token(monkeypatch):
    monkeypatch.setattr(gw_main.app.state, "gateway_api_key", "test-secret")
    response = client.get("/devices")
    assert response.status_code == 401


def test_auth_rejects_wrong_token(monkeypatch):
    monkeypatch.setattr(gw_main.app.state, "gateway_api_key", "test-secret")
    response = client.get("/devices", headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401


def test_auth_accepts_correct_token(monkeypatch):
    monkeypatch.setattr(gw_main.app.state, "gateway_api_key", "test-secret")
    response = client.get("/devices", headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200


def test_auth_disabled_when_key_not_set(monkeypatch):
    monkeypatch.setattr(gw_main.app.state, "gateway_api_key", "")
    response = client.get("/devices")
    assert response.status_code == 200


def test_register_http_transport_returns_400():
    response = client.post(
        "/devices",
        json={"hostname": "x", "base_url": "http://x.local", "transport": "http"},
    )
    assert response.status_code == 400
    assert "not supported" in response.json()["detail"]


def test_register_stdio_transport_returns_400():
    response = client.post(
        "/devices",
        json={"hostname": "x", "base_url": "http://x.local", "transport": "stdio"},
    )
    assert response.status_code == 400
    assert "not supported" in response.json()["detail"]


def test_put_unknown_device_returns_404():
    response = client.put(
        "/devices/does-not-exist",
        json={"base_url": "http://new.local", "auth_type": "none"},
    )
    assert response.status_code == 404


def test_put_unsupported_transport_with_existing_device():
    # Register a device first (will fail to reach, but registers in the map)
    client.post("/devices", json={"hostname": "put-test", "base_url": "http://192.0.2.99", "auth_type": "none"})
    response = client.put(
        "/devices/put-test",
        json={"base_url": "http://192.0.2.99", "auth_type": "none", "transport": "stdio"},
    )
    assert response.status_code == 400
    assert "not supported" in response.json()["detail"]
    client.delete("/devices/put-test")


def test_register_with_rate_limit_rps():
    response = client.post(
        "/devices",
        json={"hostname": "rate-test", "base_url": "http://192.0.2.99", "auth_type": "none", "rate_limit_rps": 5.0},
    )
    assert response.status_code == 200

    metrics = client.get("/metrics").json()
    assert "rate-test" in metrics.get("device_rate_limits", {})
    assert metrics["device_rate_limits"]["rate-test"]["rate_limit_rps"] == 5.0

    client.delete("/devices/rate-test")


def test_register_with_invalid_rate_limit_returns_400():
    response = client.post(
        "/devices",
        json={"hostname": "x", "base_url": "http://x.local", "auth_type": "none", "rate_limit_rps": -1},
    )
    assert response.status_code == 400
    assert "rate_limit_rps" in response.json()["detail"]


def test_get_device_returns_404_for_unknown():
    response = client.get("/devices/no-such-device")
    assert response.status_code == 404


def test_get_device_returns_device_data():
    client.post("/devices", json={"hostname": "getone-test", "base_url": "http://192.0.2.99", "auth_type": "none"})
    response = client.get("/devices/getone-test")
    assert response.status_code == 200
    data = response.json()
    assert data["hostname"] == "getone-test"
    assert data["base_url"] == "http://192.0.2.99"
    assert "reachable" in data
    assert "pod_active" in data
    assert "spawn_error" in data
    client.delete("/devices/getone-test")


def test_get_device_tools_returns_404_for_unknown():
    response = client.get("/devices/no-such-device/tools")
    assert response.status_code == 404


def test_get_device_tools_returns_409_when_pod_inactive():
    client.post("/devices", json={"hostname": "tools-inactive", "base_url": "http://192.0.2.99", "auth_type": "none"})
    response = client.get("/devices/tools-inactive/tools")
    assert response.status_code == 409
    assert "no active pod" in response.json()["detail"]
    client.delete("/devices/tools-inactive")


def test_large_body_returns_413():
    response = client.post(
        "/devices",
        content=b"x" * (1_048_576 + 1),
        headers={"Content-Type": "application/json", "Content-Length": str(1_048_576 + 1)},
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    "bad_hostname",
    [
        "-starts-with-dash",
        "ends-with-dash-",
        ".starts-with-dot",
        "has space",
        "has/slash",
        "a" * 254,
        "",
    ],
)
def test_invalid_hostname_returns_400(bad_hostname):
    response = client.post(
        "/devices",
        json={"hostname": bad_hostname, "base_url": "http://192.0.2.99", "auth_type": "none"},
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "good_hostname",
    ["device1", "my-device.local", "a", "sensor.lab.internal"],
)
def test_valid_hostname_accepted(good_hostname):
    response = client.post(
        "/devices",
        json={"hostname": good_hostname, "base_url": "http://192.0.2.99", "auth_type": "none"},
    )
    assert response.status_code == 200
    client.delete(f"/devices/{good_hostname}")
