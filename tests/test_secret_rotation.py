# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for credential key rotation (F-34).

Covers the multi-key codec (encrypt-with-primary / decrypt-with-any / rotate),
config resolution precedence, and the two storage-path rotation passes (SQLite
and Redis) including the loss-free handling of a credential no key can decrypt.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from device_mcp_gateway.shared.crypto import CredentialCodec, secret_keys_from_config
from device_mcp_gateway.shared.registry_backend import DeviceConfig, RedisRegistryBackend
from device_mcp_gateway.shared.rotate import rotate_redis_credentials, rotate_sqlite_credentials
from device_mcp_gateway.storage.sqlite_store import SqliteDeviceStore


@pytest.fixture
def keys():
    return Fernet.generate_key().decode(), Fernet.generate_key().decode()  # (new, old)


# ---------------------------------------------------------------------------
# Codec
# ---------------------------------------------------------------------------


def test_multifernet_encrypts_with_primary_decrypts_with_any(keys):
    new, old = keys
    old_codec = CredentialCodec.from_secret(old)
    token = old_codec.encrypt("s3cret")

    rotating = CredentialCodec.from_secret([new, old])
    assert rotating.multi_key is True
    assert rotating.decrypt(token) == "s3cret"  # old key still decrypts
    # A fresh encrypt uses the primary (new) key — unreadable by the old-only codec.
    fresh = rotating.encrypt("s3cret")
    with pytest.raises(InvalidToken):
        old_codec.decrypt(fresh)


def test_rotate_reencrypts_under_primary(keys):
    new, old = keys
    token = CredentialCodec.from_secret(old).encrypt("hunter2")
    rotating = CredentialCodec.from_secret([new, old])

    rotated = rotating.rotate(token)
    assert rotated != token
    # New-only codec (old key retired) can read the rotated value, not the original.
    new_only = CredentialCodec.from_secret(new)
    assert new_only.decrypt(rotated) == "hunter2"
    with pytest.raises(InvalidToken):
        new_only.decrypt(token)


def test_single_key_rotate_is_noop_roundtrip(keys):
    new, _ = keys
    codec = CredentialCodec.from_secret(new)
    assert codec.multi_key is False
    token = codec.encrypt("x")
    assert codec.decrypt(codec.rotate(token)) == "x"


def test_disabled_codec_passes_through():
    codec = CredentialCodec.from_secret(None)
    assert codec.enabled is False
    assert codec.encrypt("x") == "x"
    assert codec.rotate("x") == "x"


def test_config_resolution_precedence(monkeypatch, keys):
    new, old = keys
    monkeypatch.delenv("MCP_SECRET_KEY", raising=False)
    assert secret_keys_from_config({"gateway": {"secret_keys": [new, old]}}) == [new, old]
    assert secret_keys_from_config({"gateway": {"secret_key": old}}) == [old]
    # Env wins and may carry several comma-separated keys.
    monkeypatch.setenv("MCP_SECRET_KEY", f"{new}, {old}")
    assert secret_keys_from_config({"gateway": {"secret_key": "ignored"}}) == [new, old]


# ---------------------------------------------------------------------------
# SQLite rotation pass (embedded mode)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_sqlite_credentials(tmp_path, keys):
    new, old = keys
    db = str(tmp_path / "devices.db")

    # Seed a device whose credential is encrypted under the OLD key only.
    seed_store = SqliteDeviceStore(db_path=db, codec=CredentialCodec.from_secret(old))
    await seed_store.initialize()
    await seed_store.save(
        "dev1",
        {"base_url": "https://dev1", "auth_type": "api_key", "auth_config": {"key": "abc"}},
    )

    # A new-only codec cannot read it yet (proves it's old-key ciphertext).
    new_only = SqliteDeviceStore(db_path=db, codec=CredentialCodec.from_secret(new))
    loaded = {r["hostname"]: r for r in await new_only.load_all()}
    assert loaded["dev1"]["auth_config"] is None  # decrypt failed → dropped on read

    # Rotate with [new, old], then the new-only codec can read it.
    rotating = CredentialCodec.from_secret([new, old])
    rot_store = SqliteDeviceStore(db_path=db, codec=rotating)
    result = await rotate_sqlite_credentials(rot_store, rotating)
    assert result.rotated == 1 and result.failed == 0

    after = {r["hostname"]: r for r in await new_only.load_all()}
    assert after["dev1"]["auth_config"] == {"key": "abc"}

    # Idempotent: a second pass with the same codec changes nothing.
    again = await rotate_sqlite_credentials(rot_store, rotating)
    assert again.rotated == 0 and again.unchanged == 1


@pytest.mark.asyncio
async def test_rotate_sqlite_reports_undecryptable_without_dropping(tmp_path, keys):
    new, old = keys
    stranger = Fernet.generate_key().decode()  # a key not in the rotation set
    db = str(tmp_path / "devices.db")

    seed = SqliteDeviceStore(db_path=db, codec=CredentialCodec.from_secret(stranger))
    await seed.initialize()
    await seed.save("dev1", {"base_url": "https://dev1", "auth_config": {"key": "abc"}})
    raw_before = dict(await seed.iter_raw_credentials())

    rotating = CredentialCodec.from_secret([new, old])
    store = SqliteDeviceStore(db_path=db, codec=rotating)
    result = await rotate_sqlite_credentials(store, rotating)
    assert result.failed == 1 and result.rotated == 0
    assert result.failed_hostnames == ["dev1"]
    # The original ciphertext is left intact (not dropped), recoverable with the right key.
    assert dict(await store.iter_raw_credentials()) == raw_before


# ---------------------------------------------------------------------------
# Redis rotation pass (distributed mode)
#
# Uses real Redis: fakeredis returns bytes hash keys, so DeviceConfig.from_redis_hash
# (and thus backend.get_device) only round-trips against a real server. Skips
# cleanly when none is reachable; runs in CI's redis service.
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_rotate_redis_credentials(real_redis, keys):
    new, old = keys
    backend = RedisRegistryBackend(real_redis)
    await backend.initialize()

    old_codec = CredentialCodec.from_secret(old)
    await backend.set_device(
        "dev1",
        DeviceConfig(hostname="dev1", base_url="https://dev1", auth_config=old_codec.encrypt('{"key":"abc"}')),
    )
    await backend.set_device("dev2", DeviceConfig(hostname="dev2", base_url="https://dev2"))  # no creds

    rotating = CredentialCodec.from_secret([new, old])
    result = await rotate_redis_credentials(backend, rotating)
    assert result.rotated == 1 and result.failed == 0  # dev2 (no creds) is skipped, not counted

    # New-only codec can now decrypt the rotated credential.
    new_only = CredentialCodec.from_secret(new)
    cfg = await backend.get_device("dev1")
    assert new_only.decrypt(cfg.auth_config) == '{"key":"abc"}'

    # Idempotent: a second pass leaves everything already-current.
    again = await rotate_redis_credentials(backend, rotating)
    assert again.rotated == 0 and again.unchanged == 1
