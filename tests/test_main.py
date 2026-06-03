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
    monkeypatch.setattr(gw_main, "_gateway_api_key", "test-secret")
    response = client.get("/health")
    assert response.status_code == 200


def test_auth_rejects_missing_token(monkeypatch):
    monkeypatch.setattr(gw_main, "_gateway_api_key", "test-secret")
    response = client.get("/devices")
    assert response.status_code == 401


def test_auth_rejects_wrong_token(monkeypatch):
    monkeypatch.setattr(gw_main, "_gateway_api_key", "test-secret")
    response = client.get("/devices", headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401


def test_auth_accepts_correct_token(monkeypatch):
    monkeypatch.setattr(gw_main, "_gateway_api_key", "test-secret")
    response = client.get("/devices", headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200


def test_auth_disabled_when_key_not_set(monkeypatch):
    monkeypatch.setattr(gw_main, "_gateway_api_key", "")
    response = client.get("/devices")
    assert response.status_code == 200
