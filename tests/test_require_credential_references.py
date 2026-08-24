# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 §1 — a deployment may refuse inline device credentials. Off by default.

This is the second half of the §1 prerequisite, and the breaking one. §1 says a device holds
its secret by reference; until now the code only ever *permitted* that, so an archive of an
inline fleet is still a credential dump and §3's simplification stays blocked.

**Three promises, and the tests exist to hold them rather than to demonstrate the feature.**

1. **Off by default.** Turning it on is breaking for any fleet registered before references
   existed, so it is a deployment's decision when its secret store is ready — not one an
   upgrade makes for it.
2. **Existing devices keep dispatching.** The gate is on the WRITE path, not in the handler
   constructor where every other ADR-0018 rule lives. That asymmetry is deliberate: the
   rehydrate path builds the same handler from an already-stored device, so a constructor
   check would turn a policy change into an outage at the next restart.
3. **An ordinary edit still works.** A PUT that changes a rate limit and touches no credential
   is not refused, or the gate would freeze every legacy device in place.

**And the carve-out has to stay satisfiable.** A `grant_type=refresh_token` device holds a
gateway-minted token that §1a says *cannot* be by reference. Counting that as "inline" would
refuse it for failing to do something the ADR calls impossible —
`test_a_refresh_token_device_can_still_satisfy_the_gate` is what keeps that from regressing.
"""

from __future__ import annotations

import itertools
import json
import stat

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from device_mcp_gateway.credentials.resolver import audit_inline_credentials, require_references

ADMIN_KEY = "a" * 40
TENANT = "t-3f9a1c2b7d4e8065"
SECRET = "5d1e" * 12
REF = f"secret://{TENANT}/devices/erp#api-key"

_SEQ = itertools.count()


def _store(tmp_path):
    d = tmp_path / "store" / TENANT / "devices" / "erp"
    # Two stacks in one test share tmp_path (export from one, restore into the other).
    d.mkdir(parents=True, exist_ok=True)
    for name in ("api-key", "client-secret"):
        f = d / name
        f.write_text(SECRET)
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return tmp_path / "store"


def _client(monkeypatch, tmp_path, *, require: bool, secret_key: str | None = None):
    """A stack. `secret_key` must be SHARED between two stacks in an export/restore test —
    a fresh key per stack means the target cannot decrypt the archive at all, and the restore
    fails in preflight for a reason that has nothing to do with what is being tested."""
    stack = tmp_path / f"stack-{next(_SEQ)}"
    stack.mkdir()
    monkeypatch.chdir(stack)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setenv("MCP_SECRET_KEY", secret_key or Fernet.generate_key().decode())
    monkeypatch.setenv("MCP_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("MCP_CREDENTIAL_ROOT", str(_store(tmp_path)))
    if require:
        monkeypatch.setenv("MCP_REQUIRE_CREDENTIAL_REFS", "true")
    from device_mcp_gateway.main import create_app

    return TestClient(create_app())


def _auth():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _post(client, hostname, auth_block):
    return client.post(
        "/v1/devices",
        headers=_auth(),
        json={"hostname": hostname, "base_url": f"http://127.0.0.1:9/{hostname}", **auth_block},
    )


INLINE = {"auth_type": "api_key", "auth": {"api_key": "k" * 24}}
BY_REF = {"auth_type": "api_key", "auth": {"credential_ref": REF}}


# ── Promise 1: off by default ────────────────────────────────────────────────────────────


def test_the_setting_defaults_to_off():
    """Not timidity — an upgrade must not decide this for a deployment."""
    assert require_references({}) is False
    assert require_references({"gateway": {"credentials": {"root": "/x"}}}) is False


def test_inline_registration_still_works_with_the_gate_off(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, require=False)
    assert _post(client, "legacy", INLINE).status_code in (200, 201)


# ── The gate itself ──────────────────────────────────────────────────────────────────────


def test_an_inline_api_key_is_refused_with_the_gate_on(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, require=True)
    resp = _post(client, "legacy", INLINE)

    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "api_key" in detail
    assert "credential_ref" in detail, "name the field that replaces it, not just the problem"
    assert "require_references" in detail, "and how to turn it back off"


def test_a_by_reference_registration_is_accepted(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, require=True)
    assert _post(client, "erp", BY_REF).status_code in (200, 201)


def test_an_inline_oauth2_client_secret_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, require=True)
    resp = _post(
        client,
        "erp",
        {
            "auth_type": "oauth2",
            "auth": {
                "token_endpoint": "http://127.0.0.1:9/token",
                "client_id": "gw",
                "client_secret": "s" * 20,
            },
        },
    )
    assert resp.status_code == 400
    assert "client_secret" in resp.json()["detail"]


def test_a_device_with_no_credential_at_all_is_not_a_violation(monkeypatch, tmp_path):
    """`auth_type: none` is a legitimate device, not a fleet holding an inline secret."""
    client = _client(monkeypatch, tmp_path, require=True)
    assert _post(client, "open", {"auth_type": "none"}).status_code in (200, 201)


def test_a_refresh_token_device_can_still_satisfy_the_gate(monkeypatch, tmp_path):
    """§1a's carve-out must stay reachable.

    The refresh token is gateway-minted and cannot be held by reference. If it counted as an
    inline secret, this device could never be registered on a gate-on stack — refused for
    failing to do a thing the ADR states is impossible.
    """
    client = _client(monkeypatch, tmp_path, require=True)
    resp = _post(
        client,
        "erp",
        {
            "auth_type": "oauth2",
            "auth": {
                "token_endpoint": "http://127.0.0.1:9/token",
                "client_id": "gw",
                "client_secret_ref": f"secret://{TENANT}/devices/erp#client-secret",
                "grant_type": "refresh_token",
                "refresh_token": "rt-from-a-human-consent",
            },
        },
    )
    assert resp.status_code in (200, 201), resp.text


# ── Promise 2: existing devices keep working ─────────────────────────────────────────────


def test_the_rehydrate_path_is_not_gated(monkeypatch, tmp_path):
    """The outage this design avoids.

    Every other ADR-0018 rule is enforced in the handler's constructor so that registration, a
    restore and a worker rehydrating all agree. This one must not be, because rehydrating is
    reading an *already stored* device — a constructor check would mean every legacy device
    failed to load on the next restart, turning a policy change into an outage.
    """
    monkeypatch.setenv("MCP_REQUIRE_CREDENTIAL_REFS", "true")
    from device_mcp_gateway.worker.runner import _auth_from_config

    auth = _auth_from_config("api_key", json.dumps({"type": "api_key", "api_key": "k" * 24}))
    assert auth is not None
    assert auth.inline_secret_fields() == ["api_key"], "still inline — and still loaded"


def test_an_edit_that_touches_no_credential_is_allowed(monkeypatch, tmp_path):
    """Promise 3. Otherwise the gate freezes every legacy device: you could not change a rate
    limit on one without first migrating its secret."""
    client = _client(monkeypatch, tmp_path, require=False)
    assert _post(client, "legacy", INLINE).status_code in (200, 201)

    # Same stack, gate now on — as if the operator flipped it.
    monkeypatch.setenv("MCP_REQUIRE_CREDENTIAL_REFS", "true")
    client.app.state.config.setdefault("gateway", {}).setdefault("credentials", {})["require_references"] = True

    resp = client.put(
        "/v1/devices/legacy",
        headers=_auth(),
        json={"base_url": "http://127.0.0.1:9/legacy", "rate_limit_rps": 3.0},
    )
    assert resp.status_code in (200, 201), resp.text


def test_a_put_that_supplies_a_new_inline_credential_is_refused(monkeypatch, tmp_path):
    """The other half of promise 3: not touching a credential is fine, replacing one with a
    fresh inline secret is the thing the gate exists to stop."""
    client = _client(monkeypatch, tmp_path, require=True)
    assert _post(client, "erp", BY_REF).status_code in (200, 201)

    resp = client.put(
        "/v1/devices/erp",
        headers=_auth(),
        json={"base_url": "http://127.0.0.1:9/erp", "auth_type": "api_key", "auth": {"api_key": "k" * 24}},
    )
    assert resp.status_code == 400
    assert "api_key" in resp.json()["detail"]


# ── The restore path is gated too (F-67's rule) ──────────────────────────────────────────


def test_a_restore_cannot_reinstate_what_registration_would_refuse(monkeypatch, tmp_path):
    """F-67 applied to §1: a `backup:write` holder must not be able to put back a device a
    fresh registration would reject. The dry run predicts it, so the preview and the apply
    agree — which is the one thing a dry run exists to guarantee."""
    key = Fernet.generate_key().decode()
    source = _client(monkeypatch, tmp_path, require=False, secret_key=key)
    assert _post(source, "legacy", INLINE).status_code in (200, 201)
    archive = source.get("/v1/admin/backup", headers=_auth()).json()

    target = _client(monkeypatch, tmp_path, require=True, secret_key=key)
    resp = target.post("/v1/admin/restore", headers=_auth(), json={"archive": archive})
    assert resp.status_code == 200, resp.text
    preview = resp.json()
    assert preview["devices"][0]["outcome"] == "failed"
    assert "by reference" in preview["devices"][0]["reason"]

    applied = target.post("/v1/admin/restore", headers=_auth(), json={"archive": archive, "dry_run": False}).json()
    assert applied["devices"][0]["outcome"] == "failed", "the apply must agree with the preview"


# ── The inventory that makes a migration plannable ───────────────────────────────────────


class _Registry:
    def __init__(self, devices):
        self._devices = devices

    async def list_devices(self):
        return list(self._devices)


class _Boom:
    async def list_devices(self):
        raise RuntimeError("redis is down")


def _dev(hostname, payload, auth_type="api_key"):
    from device_mcp_gateway.shared.registry_backend import DeviceConfig

    return DeviceConfig(
        hostname=hostname,
        base_url="http://x",
        auth_type=auth_type,
        auth_config=json.dumps(payload) if payload else None,
    )


@pytest.mark.asyncio
async def test_the_audit_counts_only_devices_holding_a_secret_inline():
    from device_mcp_gateway.shared.crypto import CredentialCodec

    devices = [
        _dev("inline", {"type": "api_key", "api_key": "k" * 24}),
        _dev("byref", {"type": "api_key", "credential_ref": REF}),
        _dev("open", None),
    ]
    assert await audit_inline_credentials(_Registry(devices), CredentialCodec(None), required=False) == 1


@pytest.mark.asyncio
async def test_the_audit_never_breaks_startup():
    """A stack must not fail to start because a diagnostic could not be produced."""
    from device_mcp_gateway.shared.crypto import CredentialCodec

    assert await audit_inline_credentials(_Boom(), CredentialCodec(None), required=True) == 0
