# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Embedded-mode end-to-end test for the fleet MCP endpoint: one SSE session
spanning multiple devices. Mirrors test_integration.py::test_sse_transport_client_flow,
extended to two devices sharing the mock target API so the same tool
(`get_device_status`) exists on both and must come back correctly namespaced.
"""

import json
import time


def _register(client, hostname, mock_target_url):
    resp = client.post(
        "/v1/devices",
        json={"hostname": hostname, "base_url": mock_target_url, "auth_type": "none", "transport": "sse"},
    )
    assert resp.status_code == 200, f"Registration failed for {hostname}: {resp.json()}"


def _wait_pod_active(client, hostname, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        devices = client.get("/v1/devices").json().get("devices", [])
        dev = next((d for d in devices if d["hostname"] == hostname), None)
        if dev and dev.get("pod_active"):
            return
        time.sleep(0.2)
    raise AssertionError(f"Pod for {hostname} did not become active")


def test_fleet_sse_tools_list_and_call(client, mock_target_url):
    host_a, host_b = "fleet-dev-a.local", "fleet-dev-b.local"
    _register(client, host_a, mock_target_url)
    _register(client, host_b, mock_target_url)
    _wait_pod_active(client, host_a)
    _wait_pod_active(client, host_b)

    try:
        with client.stream("GET", f"/v1/fleet/sse?devices={host_a},{host_b}") as event_resp:
            assert event_resp.status_code == 200

            session_id = None
            event_name = None
            data_payload = ""
            posted_list = False
            posted_call = False
            list_result = None
            call_result = None
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
                        resp = client.post(
                            f"/v1/fleet/messages?session_id={session_id}",
                            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                        )
                        assert resp.status_code == 200
                        assert resp.json().get("status") == "accepted"
                        posted_list = True
                    elif event_name == "message" and data_payload and posted_list and list_result is None:
                        list_result = json.loads(data_payload)
                        # both devices' get_device_status, namespaced, both present
                        names = {t["name"] for t in list_result["result"]["tools"]}
                        assert names == {
                            "fleet_dev_a_local_get_device_status",
                            "fleet_dev_a_local_control_fan",
                            "fleet_dev_b_local_get_device_status",
                            "fleet_dev_b_local_control_fan",
                        }
                        resp = client.post(
                            f"/v1/fleet/messages?session_id={session_id}",
                            json={
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/call",
                                "params": {"name": "fleet_dev_b_local_get_device_status", "arguments": {}},
                            },
                        )
                        assert resp.status_code == 200
                        assert resp.json().get("status") == "accepted"
                        posted_call = True
                    elif event_name == "message" and data_payload and posted_call:
                        call_result = json.loads(data_payload)
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

            assert list_result is not None, "No tools/list SSE message received"
            assert call_result is not None, "No tools/call SSE message received"
            assert call_result["id"] == 2
            content = call_result["result"]["content"]
            tool_result = json.loads(content[0]["text"])
            assert tool_result["body"]["status"] == "online"
    finally:
        client.delete(f"/v1/devices/{host_a}")
        client.delete(f"/v1/devices/{host_b}")


def test_fleet_sse_unknown_tool_name_returns_rpc_error(client, mock_target_url):
    host = "fleet-dev-c.local"
    _register(client, host, mock_target_url)
    _wait_pod_active(client, host)

    try:
        with client.stream("GET", f"/v1/fleet/sse?devices={host}") as event_resp:
            assert event_resp.status_code == 200
            session_id = None
            event_name = None
            data_payload = ""
            posted = False
            error_result = None
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
                        resp = client.post(
                            f"/v1/fleet/messages?session_id={session_id}",
                            json={
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "tools/call",
                                "params": {"name": "does_not_exist", "arguments": {}},
                            },
                        )
                        assert resp.status_code == 200
                        posted = True
                    elif event_name == "message" and data_payload and posted:
                        error_result = json.loads(data_payload)
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

            assert error_result is not None
            assert "error" in error_result
    finally:
        client.delete(f"/v1/devices/{host}")


def test_fleet_sse_requires_devices_param(client):
    resp = client.get("/v1/fleet/sse")
    assert resp.status_code in (400, 422)


def test_fleet_sse_unknown_device_returns_404(client):
    resp = client.get("/v1/fleet/sse?devices=does-not-exist.local")
    assert resp.status_code == 404
