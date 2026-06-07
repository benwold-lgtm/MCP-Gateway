# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tests for the shared credential codec and end-to-end credential encryption.

Regression coverage for S2 finding F1: in distributed mode the gateway must
encrypt device credentials before writing them to Redis, and the worker must
decrypt them on read. Distributed mode refuses to start without a key.
"""

import json

import pytest
import fakeredis.aioredis
from cryptography.fernet import Fernet

from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.worker.runner import DeviceWorker, _auth_from_config
from device_mcp_gateway.auth.api_key import ApiKeyAuth

# --- Codec unit tests -------------------------------------------------------


def test_codec_round_trip_and_hides_plaintext():
    codec = CredentialCodec(Fernet(Fernet.generate_key()))
    secret = "supersecret-api-key"
    token = codec.encrypt(secret)
    assert token != secret
    assert secret not in token  # ciphertext must not leak the plaintext
    assert codec.decrypt(token) == secret


def test_disabled_codec_passes_through():
    codec = CredentialCodec(None)
    assert codec.enabled is False
    assert codec.encrypt("x") == "x"
    assert codec.decrypt("x") == "x"


def test_from_secret_empty_is_disabled():
    assert CredentialCodec.from_secret("").enabled is False
    assert CredentialCodec.from_secret(None).enabled is False


def test_from_secret_invalid_raises():
    with pytest.raises(ValueError):
        CredentialCodec.from_secret("not-a-valid-fernet-key")


def test_from_config_reads_env(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("MCP_SECRET_KEY", key)
    assert CredentialCodec.from_config({}).enabled is True


# --- End-to-end: gateway encrypts to Redis, worker decrypts -----------------


@pytest.mark.asyncio
async def test_distributed_credentials_encrypted_in_redis_and_decryptable_by_worker():
    codec = CredentialCodec(Fernet(Fernet.generate_key()))
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    backend = RedisRegistryBackend(r)
    registry = Registry(config={"mode": "distributed"}, backend=backend, codec=codec)

    secret = "supersecret-api-key"
    await registry.register_device(
        hostname="dev1",
        base_url="http://dev1",
        auth=ApiKeyAuth(api_key=secret, header_name="X-API-Key"),
    )

    # Read the stored config fields directly. (Real Redis decodes responses, so
    # backend.get_device() works in production; this fakeredis build doesn't
    # decode hash keys, so we read the two fields we need explicitly here.)
    def _dec(v):
        return v.decode() if isinstance(v, bytes) else v

    stored = _dec(await r.hget("device:dev1:config", "auth_config"))
    auth_type = _dec(await r.hget("device:dev1:config", "auth_type"))

    # The raw value stored in Redis must not contain the plaintext secret.
    assert secret not in stored

    # The worker decrypts it back to a usable auth object carrying the secret.
    worker = DeviceWorker(worker_id="w1", config={}, redis_client=r, codec=codec)
    decrypted = worker._decrypt_auth("dev1", stored)
    auth = _auth_from_config(auth_type, decrypted)
    assert isinstance(auth, ApiKeyAuth)
    assert auth.api_key == secret


@pytest.mark.asyncio
async def test_worker_decrypt_failure_returns_none_not_ciphertext():
    # Credentials encrypted with one key cannot be read with another.
    writer = CredentialCodec(Fernet(Fernet.generate_key()))
    reader = CredentialCodec(Fernet(Fernet.generate_key()))
    token = writer.encrypt(json.dumps({"type": "api_key", "api_key": "s3cret"}))

    worker = DeviceWorker(worker_id="w1", config={}, redis_client=None, codec=reader)
    assert worker._decrypt_auth("dev1", token) is None  # loud failure, no auth


# --- Refuse-to-start guard --------------------------------------------------


def test_distributed_without_key_refuses_to_start(monkeypatch):
    from device_mcp_gateway.main import create_app

    monkeypatch.delenv("MCP_SECRET_KEY", raising=False)
    cfg = {"registry": {"mode": "distributed"}, "gateway": {"secret_key": ""}}
    with pytest.raises(RuntimeError, match="distributed mode without MCP_SECRET_KEY"):
        create_app(override_config=cfg)


def test_distributed_allow_plaintext_override_starts(monkeypatch):
    from device_mcp_gateway.main import create_app

    monkeypatch.delenv("MCP_SECRET_KEY", raising=False)
    cfg = {
        "registry": {"mode": "distributed"},
        "gateway": {"secret_key": "", "allow_plaintext_credentials": True},
    }
    app = create_app(override_config=cfg)  # must not raise
    assert app.state.mode == "distributed"
