# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Pytest configuration for device-mcp-gateway integration tests.
"""

import os
import socket
import time
import threading
import yaml
import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI, Request
import uvicorn

# Dedicated test DB so integration tests never touch app data (db 0).
TEST_REDIS_URL = os.getenv("MCP_TEST_REDIS_URL", "redis://localhost:6379/15")


@pytest_asyncio.fixture
async def real_redis():
    """Async Redis client against a real server, for `integration` tests.

    Skips the test (rather than failing) when no Redis is reachable, so the
    fakeredis unit suite still runs anywhere. Flushes the dedicated test DB
    before and after each test for isolation.
    """
    import redis.asyncio as aioredis

    client = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        pytest.skip(f"real Redis not reachable at {TEST_REDIS_URL}")
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


# --- Mock Target API ---
mock_target_app = FastAPI(title="Mock IoT Sensor API", version="1.0.0")

MOCK_OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Mock IoT Sensor", "version": "1.0.0"},
    "servers": [{"url": "http://localhost:19876"}],
    "paths": {
        "/status": {
            "get": {
                "summary": "Get device sensor status",
                "operationId": "get_device_status",
                "responses": {"200": {"description": "Successful response"}},
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
                                "properties": {"speed": {"type": "integer", "minimum": 0, "maximum": 100}},
                                "required": ["speed"],
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Fan updated"}},
            }
        },
    },
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
    db_path = str(tmp_path_factory.mktemp("db") / "test_devices.db")
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
        "storage": {"db_path": db_path},
    }
    config_path.write_text(yaml.safe_dump(config_data))
    os.environ["MCP_CONFIG"] = str(config_path)
    # Don't bind the real metrics port across the test session; metrics content is
    # asserted directly via generate_latest, and the server start is tested in
    # isolation on an ephemeral port.
    os.environ.setdefault("MCP_METRICS_ENABLED", "0")
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
    from device_mcp_gateway.main import create_app

    config_path = os.environ.get("MCP_CONFIG", "config.yaml")
    try:
        with open(config_path) as f:
            test_cfg = yaml.safe_load(f)
    except FileNotFoundError:
        test_cfg = None

    test_app = create_app(override_config=test_cfg)
    port = _find_free_port()
    config = uvicorn.Config(test_app, host="127.0.0.1", port=port, log_level="error")
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
