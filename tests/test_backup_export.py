# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Backup export — ADR-0011 PR 1.

The property that needs the most defending is the one the ADR does not state, because the
code made it untrue: **the archive's security must not depend on which mode produced it.**
Distributed mode encrypts credentials before they reach Redis; embedded mode keeps
``DeviceConfig.auth_config`` as plaintext JSON and encrypts a layer lower, in the SQLite
store. Exporting the stored value verbatim would therefore have produced a real ciphertext
archive on one mode and a plaintext credential dump on the other — from the same
"safe by default" call, with nothing to see in either response.

So the headline test here registers a device through the **real embedded registration
path** and greps the serialised archive for the credential. Asserting on a hand-built
``DeviceConfig`` would have proved nothing: the plaintext only appears because
``_setup_device_nolock`` puts it there, and a fixture would have skipped exactly that.

The canary gets the same treatment. Its whole purpose is the archive with no credentials
in it at all, so it is tested on a fleet of ``auth_type: none`` devices — the case where a
"decrypt everything" preflight has nothing to decrypt and would pass while proving nothing.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.fernet import Fernet, InvalidToken
from fastapi.testclient import TestClient

from device_mcp_gateway.backup.envelope import (
    CANARY_PLAINTEXT,
    Argon2Params,
    PassphraseTooWeak,
    fernet_for_passphrase,
    parse_archive,
    verify_canary,
)
from device_mcp_gateway.backup.export import CiphertextExportUnavailable, build_archive
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import DeviceConfig

ADMIN_KEY = "a" * 40
DEVICE_SECRET = "SUPER-SECRET-DEVICE-KEY-9f3a2b"

# Argon2id at the shipped cost is ~0.12s per derivation; these tests derive several times,
# so the unit-level ones use a cheap cost. The *shipped* parameters are asserted separately
# from config, and the envelope always records whatever was actually used.
CHEAP_KDF = {"argon2_memory_cost_kib": 8, "argon2_iterations": 1, "argon2_lanes": 1}


# --- Test doubles for the collection layer ----------------------------------


class _FakeBackend:
    def __init__(self, changes=None, dead=None):
        self._changes = changes or {}
        self._dead = dead or {}

    async def get_last_tool_change(self, hostname):
        return self._changes.get(hostname)

    async def dead_letter_export(self, hostname, count=1000):
        return self._dead.get(hostname, [])


class _FakeRegistry:
    def __init__(self, devices, backend=None):
        self._devices = devices
        self._backend = backend or _FakeBackend()

    async def list_devices(self):
        return list(self._devices)


def _device(hostname="dev", *, auth_config=None, auth_type=None):
    return DeviceConfig(
        hostname=hostname,
        base_url=f"http://{hostname}.example.com",
        auth_type=auth_type,
        auth_config=auth_config,
    )


async def _archive(registry, codec, **over):
    kwargs = dict(
        registry=registry,
        codec=codec,
        config={"backup": {**CHEAP_KDF, "passphrase_min_length": 16}},
        gateway_version="test",
        mode="embedded",
    )
    kwargs.update(over)
    return await build_archive(**kwargs)


# --- Ciphertext archives ----------------------------------------------------


@pytest.mark.asyncio
async def test_ciphertext_archive_opens_with_the_same_key_and_not_another():
    key = Fernet.generate_key().decode()
    codec = CredentialCodec.from_secret(key)
    stored = codec.encrypt(json.dumps({"api_key": DEVICE_SECRET}))
    archive = await _archive(_FakeRegistry([_device(auth_config=stored, auth_type="api_key")]), codec)

    blob = archive["devices"][0]["auth_config"]
    assert json.loads(codec.decrypt(blob))["api_key"] == DEVICE_SECRET

    other = CredentialCodec.from_secret(Fernet.generate_key().decode())
    with pytest.raises(InvalidToken):
        other.decrypt(blob)


@pytest.mark.asyncio
async def test_a_ciphertext_export_without_a_key_is_refused_not_downgraded():
    """The failure that would otherwise be silent: an archive labelled ciphertext,
    containing plaintext, produced by the *default* call."""
    with pytest.raises(CiphertextExportUnavailable) as exc:
        await _archive(_FakeRegistry([_device()]), CredentialCodec(None))
    assert "MCP_SECRET_KEY" in str(exc.value)
    assert "portable" in str(exc.value)


@pytest.mark.asyncio
async def test_a_credential_under_an_older_rotation_key_is_not_double_wrapped():
    """During a key rotation both keys decrypt and only the first encrypts.

    A "is this already current?" test would call an old-key credential plaintext and
    encrypt it a second time. The archive would still look fine — every field ciphertext,
    counts right — and would restore credentials that decrypt to *ciphertext*.
    """
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    written_by_old = CredentialCodec.from_secret(old).encrypt(json.dumps({"api_key": DEVICE_SECRET}))

    rotating = CredentialCodec.from_secret([new, old])  # new is primary, both decrypt
    archive = await _archive(_FakeRegistry([_device(auth_config=written_by_old, auth_type="api_key")]), rotating)

    recovered = json.loads(rotating.decrypt(archive["devices"][0]["auth_config"]))
    assert recovered == {"api_key": DEVICE_SECRET}, "credential should decrypt to JSON, not to more ciphertext"
    # And it is now under the *primary* key, so it survives retiring the old one.
    assert CredentialCodec.from_secret(new).is_current(archive["devices"][0]["auth_config"])


# --- Portable archives ------------------------------------------------------


@pytest.mark.asyncio
async def test_portable_archive_is_key_independent():
    """The job it exists for: opening an archive on a stack that does not have the key.

    Proven by decrypting with a codec built from *no key at all*, which is the disaster
    case the portable kind is for — MCP_SECRET_KEY lost, archive still readable.
    """
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    stored = codec.encrypt(json.dumps({"api_key": DEVICE_SECRET}))
    passphrase = "correct horse battery staple"

    archive = await _archive(
        _FakeRegistry([_device(auth_config=stored, auth_type="api_key")]),
        codec,
        kind="portable",
        passphrase=passphrase,
    )

    # A reader with the passphrase and nothing else.
    params = Argon2Params.from_envelope(archive["kdf"])
    fernet = fernet_for_passphrase(passphrase, params)
    recovered = json.loads(fernet.decrypt(archive["devices"][0]["auth_config"].encode()).decode())
    assert recovered == {"api_key": DEVICE_SECRET}

    with pytest.raises(InvalidToken):
        fernet_for_passphrase("the wrong passphrase entirely", params).decrypt(
            archive["devices"][0]["auth_config"].encode()
        )


@pytest.mark.asyncio
async def test_the_envelope_records_the_parameters_actually_used():
    """Raising the cost later must not orphan existing archives, so the reader derives
    from what the archive declares rather than from today's config."""
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    archive = await _archive(
        _FakeRegistry([_device()]),
        codec,
        kind="portable",
        passphrase="x" * 20,
        config={
            "backup": {
                "argon2_memory_cost_kib": 16,
                "argon2_iterations": 2,
                "argon2_lanes": 1,
                "passphrase_min_length": 16,
            }
        },
    )
    kdf = archive["kdf"]
    assert kdf["algorithm"] == "argon2id"
    assert (kdf["memory_cost_kib"], kdf["iterations"], kdf["lanes"]) == (16, 2, 1)
    assert kdf["passphrase_min_length"] == 16
    assert len(base64.b64decode(kdf["salt"])) == 16, "a per-archive random salt"

    # Two archives never share a salt.
    second = await _archive(
        _FakeRegistry([_device()]),
        codec,
        kind="portable",
        passphrase="x" * 20,
        config={"backup": {**CHEAP_KDF, "passphrase_min_length": 16}},
    )
    assert second["kdf"]["salt"] != kdf["salt"]


@pytest.mark.asyncio
async def test_a_passphrase_below_the_floor_is_refused():
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    with pytest.raises(PassphraseTooWeak):
        await _archive(_FakeRegistry([_device()]), codec, kind="portable", passphrase="short")
    with pytest.raises(PassphraseTooWeak):
        await _archive(_FakeRegistry([_device()]), codec, kind="portable", passphrase=None)


# --- The canary -------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_canary_makes_the_preflight_total_on_an_archive_with_no_credentials():
    """A fleet of unauthenticated devices has no ciphertext to test.

    Without the canary a wrong-key restore of this archive would sail through preflight
    and the operator would find out at the far end. The canary is the only thing in it
    that can fail.
    """
    key = Fernet.generate_key().decode()
    codec = CredentialCodec.from_secret(key)
    archive = await _archive(_FakeRegistry([_device("a", auth_type="none"), _device("b", auth_type="none")]), codec)

    assert all(d["auth_config"] is None for d in archive["devices"]), "nothing else here can be decrypt-tested"
    verify_canary(archive, codec)  # right key: passes

    wrong = CredentialCodec.from_secret(Fernet.generate_key().decode())
    with pytest.raises(Exception) as exc:
        verify_canary(archive, wrong)
    assert "MCP_SECRET_KEY" in str(exc.value), "the error must name the likely cause, not raise InvalidToken"


@pytest.mark.asyncio
async def test_the_portable_canary_names_the_passphrase_as_the_likely_cause():
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    archive = await _archive(_FakeRegistry([_device(auth_type="none")]), codec, kind="portable", passphrase="y" * 20)
    params = Argon2Params.from_envelope(archive["kdf"])

    verify_canary(archive, fernet_for_passphrase("y" * 20, params))
    with pytest.raises(Exception) as exc:
        verify_canary(archive, fernet_for_passphrase("z" * 20, params))
    assert "passphrase" in str(exc.value)


def test_canary_plaintext_is_not_a_secret_but_is_version_tagged():
    """It is public by design — what matters is that it is *this* archive format's."""
    assert CANARY_PLAINTEXT == b"device-mcp-gateway/backup/canary/v1"


# --- Framing ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_archive_carries_registration_inputs_not_runtime_state():
    """Runtime state describes the stack that produced the archive, not the one restoring
    it. Carrying `reachable`/`last_check` across would assert facts about a fleet nothing
    has contacted — which is the F-66 mistake, in a new place."""
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    cfg = _device()
    cfg.pod_active = True
    cfg.reachable = True
    cfg.last_check = 12345.0
    cfg.worker_id = "worker-3"
    cfg.spec_hash = "deadbeef"
    cfg.tools_revision = 7

    archive = await _archive(_FakeRegistry([cfg]), codec)
    record = archive["devices"][0]

    for runtime in ("pod_active", "reachable", "last_check", "worker_id", "spec_hash"):
        assert runtime not in record, f"{runtime} is a measurement of the exporting stack"
    assert record["base_url"] == cfg.base_url
    assert record["tools_revision"] == 7, "governance counter travels — resetting it reads as a tool-set rollback"


@pytest.mark.asyncio
async def test_governance_and_dead_letters_are_collected():
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    backend = _FakeBackend(
        changes={"dev": {"added": ["t1"], "revision": 3}},
        dead={"dev": [{"id": "1-0", "fields": {"message": '{"method":"tools/call"}', "reason": "timeout"}}]},
    )
    registry = _FakeRegistry([_device()], backend)

    without = await _archive(registry, codec)
    assert without["tool_changes"]["dev"]["revision"] == 3, "governance history is always included"
    assert without["dead_letters"] == {}, "dead letters are opt-in"
    assert without["counts"]["dead_letters"] == 0

    with_dlq = await _archive(registry, codec, include_deadletters=True)
    entry = with_dlq["dead_letters"]["dev"][0]
    assert entry["id"] == "1-0"
    assert "message" in entry["fields"], "the payload is what makes a restored dead letter replayable"
    assert with_dlq["counts"]["dead_letters"] == 1


@pytest.mark.asyncio
async def test_parse_archive_rejects_a_file_with_no_canary():
    """Refusing here is refusing to run a preflight that cannot be made total."""
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    archive = await _archive(_FakeRegistry([_device()]), codec)
    parse_archive(json.dumps(archive))  # intact: fine

    del archive["canary"]
    with pytest.raises(Exception) as exc:
        parse_archive(json.dumps(archive))
    assert "canary" in str(exc.value)


# --- Through the real embedded registration path ----------------------------


def _client(monkeypatch, *, secret_key: str | None):
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setenv("MCP_ALLOW_PRIVATE_TARGETS", "true")
    if secret_key:
        monkeypatch.setenv("MCP_SECRET_KEY", secret_key)
    else:
        monkeypatch.delenv("MCP_SECRET_KEY", raising=False)
    from device_mcp_gateway.main import create_app

    return TestClient(create_app())


def _auth():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def test_an_embedded_export_never_contains_the_plaintext_credential(monkeypatch):
    """The mode-dependence bug, caught the only way it can be.

    Embedded mode stores ``auth_config`` as plaintext JSON in the DeviceConfig — so this
    registers a device for real and searches the whole serialised archive for the secret.
    A hand-built config would not have exercised the code that puts it there.
    """
    key = Fernet.generate_key().decode()
    client = _client(monkeypatch, secret_key=key)

    resp = client.post(
        "/v1/devices",
        headers=_auth(),
        json={
            "hostname": "backup-dev",
            "base_url": "http://127.0.0.1:9",  # discard port: unreachable, instantly
            "auth_type": "api_key",
            "auth": {"api_key": DEVICE_SECRET},
        },
    )
    assert resp.status_code in (200, 201), resp.text

    # It really is plaintext at rest in this mode — the premise of the test.
    stored = client.app.state.registry.get_profile("backup-dev").config.auth_config
    assert DEVICE_SECRET in (stored or ""), "embedded mode stores plaintext; if this changed, revisit the export"

    archive = client.get("/v1/admin/backup", headers=_auth()).json()
    assert DEVICE_SECRET not in json.dumps(archive), "the archive leaked a credential in plaintext"

    codec = CredentialCodec.from_secret(key)
    record = next(d for d in archive["devices"] if d["hostname"] == "backup-dev")
    assert json.loads(codec.decrypt(record["auth_config"]))["api_key"] == DEVICE_SECRET
    verify_canary(archive, codec)


def test_export_requires_its_scope_and_portable_requires_its_own(monkeypatch):
    monkeypatch.setenv("MCP_VIEWER_KEY", "v" * 40)
    client = _client(monkeypatch, secret_key=Fernet.generate_key().decode())

    viewer = {"Authorization": f"Bearer {'v' * 40}"}
    assert client.get("/v1/admin/backup", headers=viewer).status_code == 403

    # An admin holds every scope, including export-portable.
    assert client.get("/v1/admin/backup", headers=_auth()).status_code == 200

    # A principal with backup:read but not backup:export-portable is refused the
    # portable kind specifically — the grant that is never implied.
    from device_mcp_gateway.rbac import Principal, SCOPE_BACKUP_READ

    backup_only = Principal(subject="key:backup", scopes=frozenset({SCOPE_BACKUP_READ}), auth_method="api_key")
    client.app.state.authenticator._keys["b" * 40] = backup_only
    headers = {"Authorization": f"Bearer {'b' * 40}"}

    assert client.get("/v1/admin/backup", headers=headers).status_code == 200
    portable = client.post("/v1/admin/backup", headers=headers, json={"kind": "portable", "passphrase": "q" * 20})
    assert portable.status_code == 403
    assert "backup:export-portable" in portable.json()["detail"]


def test_a_ciphertext_export_with_no_key_configured_is_a_409(monkeypatch):
    client = _client(monkeypatch, secret_key=None)
    resp = client.get("/v1/admin/backup", headers=_auth())
    assert resp.status_code == 409
    assert "MCP_SECRET_KEY" in resp.json()["detail"]


def test_the_backup_role_cannot_take_a_portable_archive():
    """A scheduled backup job holds read+write and stops there — the key-independent
    credential dump stays an explicit operator action."""
    from device_mcp_gateway.rbac import (
        SCOPE_BACKUP_EXPORT_PORTABLE,
        SCOPE_BACKUP_READ,
        SCOPE_BACKUP_WRITE,
        SCOPE_DEVICES_WRITE,
        SCOPE_TOOLS_CALL,
        scopes_for_role,
    )

    scopes = scopes_for_role("backup")
    assert SCOPE_BACKUP_READ in scopes and SCOPE_BACKUP_WRITE in scopes
    assert SCOPE_BACKUP_EXPORT_PORTABLE not in scopes
    assert SCOPE_TOOLS_CALL not in scopes and SCOPE_DEVICES_WRITE not in scopes

    for role in ("operator", "viewer", "auditor", "caller"):
        assert not (
            scopes_for_role(role) & {SCOPE_BACKUP_READ, SCOPE_BACKUP_WRITE}
        ), f"{role} must not read backups — an archive is every device's URL and config"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_dead_letter_export_keeps_the_payload_the_triage_view_drops(real_redis):
    """Why this needed its own backend method rather than reusing ``dead_letter_list``.

    The triage reader keeps enough to eyeball a queue and drops ``message`` — the actual
    JSON-RPC call. An archive built from it would restore dead letters that can never be
    replayed, and would look complete doing it: right count, right ids, right reasons.

    Real Redis rather than fakeredis: these are streams read back through the same decode
    path the gateway uses.
    """
    from device_mcp_gateway.shared.keys import KEYS
    from device_mcp_gateway.shared.registry_backend import RedisRegistryBackend

    backend = RedisRegistryBackend(real_redis)
    call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "reboot"}})
    await real_redis.xadd(
        KEYS.device_calls_dead("dev"),
        {"request_id": "r1", "session_id": "s1", "message": call, "reason": "timeout", "ts": "123"},
    )

    triage = await backend.dead_letter_list("dev")
    assert triage[0]["reason"] == "timeout"
    assert "message" not in triage[0], "premise: the triage view is lossy"

    exported = await backend.dead_letter_export("dev")
    assert len(exported) == 1
    assert exported[0]["fields"]["message"] == call, "the payload must survive a backup"
    assert exported[0]["fields"]["request_id"] == "r1"
    assert exported[0]["id"], "entry ids preserve ordering and incident correlation"


def test_the_shipped_argon2_parameters_match_the_adr():
    """ADR-0011 fixes m=64 MiB, t=3, p=4. A silent weakening should fail here."""
    from device_mcp_gateway.cfg import _defaults

    backup = _defaults()["backup"]
    assert backup["argon2_memory_cost_kib"] == 65536
    assert backup["argon2_iterations"] == 3
    assert backup["argon2_lanes"] == 4
    assert backup["passphrase_min_length"] == 16


# --- Endpoint fingerprints in the archive (ADR-0015) ------------------------


def _register_plain(client, hostname, base_url="http://127.0.0.1:9"):
    resp = client.post("/v1/devices", headers=_auth(), json={"hostname": hostname, "base_url": base_url})
    assert resp.status_code in (200, 201), resp.text
    return resp


def test_the_archive_carries_the_endpoint_fingerprint(monkeypatch):
    """Without this the control is void from the first restore onward.

    An archive that omits the pin does not lose a fact the new stack can re-derive — it
    silently re-runs trust-on-first-use against whatever now answers at ``base_url``,
    which is the exact substitution ADR-0015 exists to catch.
    """
    client = _client(monkeypatch, secret_key=Fernet.generate_key().decode())
    spki = "a1" * 32
    resp = client.post(
        "/v1/devices",
        headers=_auth(),
        json={
            "hostname": "alpha",
            "base_url": "https://127.0.0.1:9",
            "expected_tls_spki_sha256": spki,
            "fingerprint_policy": "enforce",
        },
    )
    assert resp.status_code in (200, 201), resp.text

    archive = client.get("/v1/admin/backup", headers=_auth()).json()
    block = archive["devices"][0]["fingerprint"]

    assert block["tls_spki_sha256"] == spki
    assert block["fingerprint_state"] == "pinned"
    # A per-device `enforce` that silently reverts to the deployment default on restore
    # would downgrade exactly the devices chosen for being worth protecting.
    assert block["fingerprint_policy"] == "enforce"


def test_the_fingerprint_block_is_present_even_when_nothing_is_pinned(monkeypatch):
    """Its presence is how a reader tells a fingerprint-aware archive from an older one,
    and those two call for different advice."""
    client = _client(monkeypatch, secret_key=Fernet.generate_key().decode())
    _register_plain(client, "alpha")

    block = client.get("/v1/admin/backup", headers=_auth()).json()["devices"][0]["fingerprint"]
    assert block["tls_spki_sha256"] is None
    assert block["fingerprint_state"] == "unpinned"


def test_the_archive_does_not_carry_runtime_measurements(monkeypatch):
    """The fingerprint travels because it is a trusted baseline, not because observed
    values travel. `reachable`/`last_check` are measurements of one stack (F-66)."""
    client = _client(monkeypatch, secret_key=Fernet.generate_key().decode())
    _register_plain(client, "alpha")

    record = client.get("/v1/admin/backup", headers=_auth()).json()["devices"][0]
    for field in ("reachable", "last_check", "pod_active", "worker_id", "spec_hash"):
        assert field not in record, f"{field} is a measurement and must not be restored"
