"""
Pytest configuration for device-mcp-gateway integration tests.
"""
import os
import socket
import time
import threading
import yaml
import pytest
import httpx
from fastapi import FastAPI, Request
import uvicorn

# --- Mock Target API ---
mock_target_app = FastAPI(title='Mock IoT Sensor API', version='1.0.0')

MOCK_OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Mock IoT Sensor", "version": "1.0.0"},
    "servers": [{"url": "http://localhost:19876"}],
    "paths": {
        "/status": {
            "get": {
                "summary": "Get device sensor status",
                "operationId": "get_device_status",
                "responses": {"200": {"description": "Successful response"}}
            }
        },
        "/control/fan": {
            "post": {
                "summary": "Control the cooling fan",
                "operationId": "control_fan",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "speed": {"type": "integer", "minimum": 0, "maximum": 100}
                                },
                                "required": ["speed"]
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Fan updated"}}
            }
        }
    }
}

@mock_target_app.get("/status")
async def get_status():
    return {"status": "online", "temp": 24.5, "humidity": 45}

@mock_target_app.post("/control/fan")
async def control_fan(request: Request):
    data = await request.json()
    return {"fan_speed": data.get("speed"), "state": "running"}

@mock_target_app.get("/openapi.json")
async def serve_spec():
    return MOCK_OPENAPI_SPEC

# Ensure FastAPI returns our static spec for the automatic openapi route
def _static_openapi():
    return MOCK_OPENAPI_SPEC

mock_target_app.openapi = _static_openapi

# --- Test configuration helpers ---

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session", autouse=True)
def test_config(tmp_path_factory):
    """Use a fast test config during integration tests."""
    config_path = tmp_path_factory.mktemp("config") / "test_config.yaml"
    config_data = {
        "server": {"host": "127.0.0.1", "port": 8000},
        "registry": {
            "health_check_interval": 1,
            "spec_poll_interval": 1,
            "spec_cache_ttl": 60,
            "max_concurrent_pods": 10,
        },
        "auth": {"type": "api_key"},
        "transport": {"default": "sse"},
        "logging": {"level": "INFO"},
    }
    config_path.write_text(yaml.safe_dump(config_data))
    os.environ["MCP_CONFIG"] = str(config_path)
    yield


@pytest.fixture(scope="session")
def mock_target_url():
    """Starts the mock target API in the background on a dynamic port."""
    port = _find_free_port()
    MOCK_OPENAPI_SPEC["servers"] = [{"url": f"http://127.0.0.1:{port}"}]
    config = uvicorn.Config(mock_target_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(1.5)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


@pytest.fixture(scope="module")
def gateway_url():
    import importlib
    import device_mcp_gateway.main as main
    importlib.reload(main)

    port = _find_free_port()
    config = uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.5)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=3.0)

@pytest.fixture(scope="module")
def client(gateway_url):
    with httpx.Client(base_url=gateway_url, timeout=httpx.Timeout(10.0, read=30.0)) as client:
        yield client

# Global registry for test results to avoid TestClient blocking issues across threads
test_results = {}
