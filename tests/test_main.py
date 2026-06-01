from fastapi.testclient import TestClient
from device_mcp_gateway.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "active_pods" in data
    assert "registered_devices" in data
    assert "version" in data
