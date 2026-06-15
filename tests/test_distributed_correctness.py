# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Batch R2 — distributed-mode correctness regressions.

Three bugs that a third-party review found surviving the v0.1.0 release, each of
which broke distributed mode for a real workflow while embedded mode hid it:

  1. Manifest cache crash + lossy round-trip: ``RequestBodySpec.binary_fields`` is a
     ``set`` that ``json.dumps`` can't encode, and the dict→manifest rebuild dropped
     ``request_body`` / ``param_wire_names`` entirely — so any device with a request
     body was broken end-to-end.
  2. PUT-wipes-credentials: a PUT that omitted auth reconstructed credentials from the
     stored *ciphertext*, failed to parse it as JSON, and silently re-registered the
     device with no auth.
  3. Unassign mis-route: unassign went through the shared competing-consumers group, so
     it landed on one arbitrary worker that usually wasn't the pod's owner — the pod was
     never torn down and a PUT-replace never applied its new config.
"""

import asyncio
import json

import fakeredis.aioredis
import pytest

from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.core.translator import (
    MULTIPART_CONTENT,
    McpManifest,
    McpTool,
    RequestBodySpec,
)
from device_mcp_gateway.registry.server import Registry, _auth_from_record
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import (
    _ASSIGNMENTS_STREAM,
    _UNASSIGN_STREAM,
    MemoryRegistryBackend,
    RedisRegistryBackend,
)
from device_mcp_gateway.worker.health import _manifest_to_dict
from device_mcp_gateway.worker.runner import DeviceWorker, _dict_to_manifest

WORKER_CONFIG = {"registry": {"health_check_interval": 30}}


def _redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _manifest_with_binary_body() -> McpManifest:
    """A manifest whose one tool has a multipart body with binary file fields and a
    F-04 wire-name rename — the exact shape that crashed/round-tripped lossily."""
    tool = McpTool(
        name="upload",
        description="upload a file",
        schema={"type": "object"},
        method="POST",
        path="/upload",
        request_body=RequestBodySpec(content_type=MULTIPART_CONTENT, binary_fields={"file", "thumbnail"}),
        param_wire_names={"id_": "id"},
    )
    return McpManifest(server_name="mcp-dev1", server_version="1.0.0", hostname="dev1", tools=[tool])


# --- Claim 1: manifest serialization round-trip ------------------------------


def test_manifest_to_dict_is_json_serializable_with_binary_body():
    d = _manifest_to_dict(_manifest_with_binary_body())
    body = d["tools"][0]["request_body"]
    # binary_fields must be a JSON-encodable list now (it was a set → json.dumps crash).
    assert isinstance(body["binary_fields"], list)
    assert sorted(body["binary_fields"]) == ["file", "thumbnail"]
    # The whole dict must serialize — this is exactly what set_manifest does.
    json.dumps(d)


@pytest.mark.asyncio
async def test_set_manifest_does_not_crash_on_binary_body():
    backend = RedisRegistryBackend(_redis())
    # Pre-fix this raised "Object of type set is not JSON serializable".
    await backend.set_manifest("dev1", _manifest_to_dict(_manifest_with_binary_body()), ttl=3600)
    assert await backend.get_manifest("dev1") is not None


@pytest.mark.asyncio
async def test_manifest_roundtrip_restores_request_body_and_wire_names():
    backend = RedisRegistryBackend(_redis())
    await backend.set_manifest("dev1", _manifest_to_dict(_manifest_with_binary_body()), ttl=3600)

    rebuilt = _dict_to_manifest(await backend.get_manifest("dev1"))
    tool = rebuilt.tools[0]
    assert tool.request_body is not None, "request_body was dropped on round-trip"
    assert tool.request_body.content_type == MULTIPART_CONTENT
    # Restored to a set so the adapter's `k in spec.binary_fields` behaves as in embedded.
    assert tool.request_body.binary_fields == {"file", "thumbnail"}
    assert isinstance(tool.request_body.binary_fields, set)
    assert tool.param_wire_names == {"id_": "id"}


# --- Claim 2: PUT must not wipe stored credentials ---------------------------


def test_auth_from_record_cannot_parse_ciphertext():
    # Documents the root cause: Fernet ciphertext isn't JSON, so the old PUT path
    # reconstructed None and silently wiped the device's credentials.
    token = "gAAAAABnot-actually-json-just-opaque-ciphertext"
    assert _auth_from_record({"auth_config": token, "auth_type": "api_key"}) is None


@pytest.mark.asyncio
async def test_replace_device_keep_auth_preserves_encrypted_credentials():
    from cryptography.fernet import Fernet

    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    # MemoryRegistryBackend stores the DeviceConfig as-is (the real-Redis hash
    # round-trip is covered by the integration tier); the keep_auth logic + codec
    # encryption are what this test exercises.
    backend = MemoryRegistryBackend()
    reg = Registry(config={"mode": "distributed"}, backend=backend, codec=codec)

    auth = ApiKeyAuth(api_key="s3cret-key", location="header", header_name="X-API-Key")
    await reg.register_device("dev1", "http://dev1", auth=auth)

    before = await backend.get_device("dev1")
    assert before.auth_type == "api_key"
    cipher_before = before.auth_config
    assert cipher_before and "s3cret-key" not in cipher_before  # encrypted at rest

    # PUT with no auth field → keep_auth path; only base_url changes.
    await reg.replace_device("dev1", base_url="http://dev1-new", keep_auth=True)

    after = await backend.get_device("dev1")
    assert after.base_url == "http://dev1-new"  # the intended change applied
    assert after.auth_type == "api_key"  # auth NOT wiped
    assert after.auth_config == cipher_before  # ciphertext carried through verbatim
    assert json.loads(codec.decrypt(after.auth_config))["api_key"] == "s3cret-key"


@pytest.mark.asyncio
async def test_replace_device_with_new_auth_still_updates_it():
    from cryptography.fernet import Fernet

    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    # MemoryRegistryBackend stores the DeviceConfig as-is (the real-Redis hash
    # round-trip is covered by the integration tier); the keep_auth logic + codec
    # encryption are what this test exercises.
    backend = MemoryRegistryBackend()
    reg = Registry(config={"mode": "distributed"}, backend=backend, codec=codec)

    await reg.register_device(
        "dev1", "http://dev1", auth=ApiKeyAuth(api_key="old", location="header", header_name="X-API-Key")
    )
    # A PUT that DOES carry auth must replace it (keep_auth stays False).
    await reg.replace_device(
        "dev1",
        base_url="http://dev1",
        auth=ApiKeyAuth(api_key="new", location="header", header_name="X-API-Key"),
        keep_auth=False,
    )
    after = await backend.get_device("dev1")
    assert json.loads(codec.decrypt(after.auth_config))["api_key"] == "new"


# --- Claim 3: unassign must reach the pod's actual owner ---------------------


@pytest.mark.asyncio
async def test_unassign_routes_to_broadcast_stream_not_shared_group():
    backend = RedisRegistryBackend(_redis())
    r = backend._r
    await backend.publish_assignment("assign", "dev1")
    await backend.publish_assignment("unassign", "dev1")
    # assign is load-balanced (shared group); unassign is broadcast so every worker
    # — including the actual owner — sees it.
    assert await r.xlen(_ASSIGNMENTS_STREAM) == 1
    assert await r.xlen(_UNASSIGN_STREAM) == 1


class _StubPod:
    def stop(self):
        pass

    async def aclose(self):
        pass


async def _own(worker: DeviceWorker, hostname: str) -> None:
    """Make ``worker`` the live owner of ``hostname`` (claim + assigned + stub pod)."""
    worker._backend = RedisRegistryBackend(worker._r)
    await worker._r.set(f"claim:{hostname}", worker._id)
    await worker._r.sadd(f"worker:{worker._id}:devices", hostname)
    worker._assigned.add(hostname)
    worker._pods[hostname] = _StubPod()


@pytest.mark.asyncio
async def test_kill_pod_noops_for_non_owner():
    # The broadcast delivers unassign to every worker; a worker that doesn't own the
    # device must leave the real owner's pod alone (idempotent teardown).
    r = _redis()
    owner = DeviceWorker(worker_id="A", config=WORKER_CONFIG, redis_client=r)
    other = DeviceWorker(worker_id="B", config=WORKER_CONFIG, redis_client=r)
    await _own(owner, "dev1")
    other._backend = RedisRegistryBackend(r)

    await other._kill_pod("dev1")  # B is not the owner
    assert "dev1" in owner._assigned  # still running on A
    assert await r.get("claim:dev1") == "A"  # A's claim untouched


@pytest.mark.asyncio
async def test_unassign_broadcast_tears_down_pod_on_the_owner():
    r = _redis()
    owner = DeviceWorker(worker_id="A", config=WORKER_CONFIG, redis_client=r)
    other = DeviceWorker(worker_id="B", config=WORKER_CONFIG, redis_client=r)
    await _own(owner, "dev1")
    await _own(other, "dev2")  # B owns a different device

    t_owner = asyncio.create_task(owner._consume_unassignments())
    t_other = asyncio.create_task(other._consume_unassignments())
    await asyncio.sleep(0.1)  # let both tailers reach XREAD "$"

    # Registry publishes the unassign (broadcast) after the tailers are live.
    await owner._backend.publish_assignment("unassign", "dev1")

    try:
        for _ in range(100):  # bounded wait for the owner to tear down
            if "dev1" not in owner._assigned:
                break
            await asyncio.sleep(0.05)
    finally:
        owner._stop_event.set()
        other._stop_event.set()
        await asyncio.gather(t_owner, t_other, return_exceptions=True)

    assert "dev1" not in owner._assigned, "owner did not tear down its pod on unassign"
    assert await r.get("claim:dev1") is None  # claim released so another worker can take it
    assert "dev2" in other._assigned  # the non-owner's own device is untouched
