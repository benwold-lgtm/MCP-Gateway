"""A device's endpoint trust record must survive an update (ADR-0015).

**The defect these cover was found on a live cluster, not here.** A PUT that changed only
``rate_limit_rps`` — no credential touched — cleared ``fingerprint_state``,
``fingerprint_pinned_at`` and ``tls_spki_sha256``. One health check later the device
re-pinned by trust-on-first-use to whatever key it next saw and reported ``pinned`` again,
with nothing logged. The end state was indistinguishable from a device that had never lost
its pin, which is why nothing noticed for as long as it did.

Three properties make it a security bug rather than an inconvenience:

* ADR-0015 §8's out-of-band pre-pinning — an operator verifying an SPKI by hand — was
  destroyed by the next unrelated edit.
* The re-pin runs through the ordinary first-sight path, so it yields **no**
  ``key_changed`` verdict and no quarantine. The alarm ADR-0015 exists to raise cannot
  fire, because the gateway believes it is meeting the device for the first time.
* Anyone holding ``devices:write`` could therefore clear a pin with a no-op edit.

The cause was known and defended against on the *other* caller of ``replace_device``:
``plan_fingerprint_restore`` writes the live values back precisely because the rebuild
"builds a fresh ``DeviceConfig`` from registration inputs alone". One caller compensated;
the other did not, and no test paired a pin with a PUT. That gap is what this file closes.

Distributed mode gets the direct-registry tests because that is where the defect was
observed; embedded gets the route-level ones, so the fix is proven at the layer an operator
actually touches.
"""

from __future__ import annotations

import copy
import itertools

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.backup.restore import _FINGERPRINT_FIELDS
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.security import fingerprint as fp
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import DeviceConfig, MemoryRegistryBackend

SPKI_A = "a" * 64
SPKI_B = "b" * 64
ADMIN_KEY = "test-admin-key"
_STACK_SEQ = itertools.count()


def _pinned_fields(spki: str | None = SPKI_A, *, state: str = fp.STATE_PINNED, **extra):
    fields: dict = {"fingerprint_state": state}
    if spki is not None:
        fields.update(
            {
                "tls_spki_sha256": spki,
                "tls_cert_sha256": "c" * 64,
                "tls_issuer": "CN=device",
                "tls_not_after": "2036-01-01T00:00:00+00:00",
                "fingerprint_pinned_at": 1700000000.0,
            }
        )
    fields.update(extra)
    return fields


class _StoringBackend(MemoryRegistryBackend):
    """``MemoryRegistryBackend`` that STORES rather than aliases.

    The stock double keeps the caller's ``DeviceConfig`` by reference on ``set_device`` and
    hands the same object back from ``get_device``. Every assertion about "was it
    persisted?" is then answered by the object the code under test is still holding, so
    writing to the backend and mutating the returned record become indistinguishable — two
    mutants of this fix survived a full pass because of it.

    The real backend serialises to a Redis hash and parses a fresh object back, so copying
    at both boundaries is the faithful imitation. (``RedisRegistryBackend`` over fakeredis
    would be more faithful still, but the installed fakeredis ignores
    ``decode_responses=True`` and returns bytes keys, so ``get_device`` silently yields
    ``None`` — a double that lies in a different direction.)
    """

    async def set_device(self, hostname, config):
        await super().set_device(hostname, copy.copy(config))

    async def get_device(self, hostname):
        cfg = await super().get_device(hostname)
        return copy.copy(cfg) if cfg is not None else None


async def _distributed(hostname: str = "dev1", *, auth=None, **pin):
    """A distributed registry holding one pinned device."""
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    backend = _StoringBackend()
    reg = Registry(config={"mode": "distributed"}, backend=backend, codec=codec)
    await reg.register_device(hostname, "http://dev1", auth=auth)
    await backend.update_device_fields(hostname, **_pinned_fields(**pin))
    return reg, backend


# --- distributed: the mode the defect was observed in -------------------------------


@pytest.mark.asyncio
async def test_an_ordinary_edit_does_not_unpin_the_device():
    """The exact reproduction: change a rate limit, keep the pin.

    ``keep_auth=True`` is the ordinary-edit path — a PUT carrying no credential field.
    """
    reg, backend = await _distributed()

    await reg.replace_device("dev1", base_url="http://dev1", rate_limit_rps=7, keep_auth=True)

    after = await backend.get_device("dev1")
    assert after.rate_limit_rps == 7, "the intended change must still apply"
    assert after.fingerprint_state == fp.STATE_PINNED
    assert after.tls_spki_sha256 == SPKI_A
    assert after.fingerprint_pinned_at == 1700000000.0, "re-pinning is not preserving"


@pytest.mark.asyncio
async def test_the_returned_record_agrees_with_the_stored_one():
    """The caller renders what it is handed, so both copies have to carry the pin.

    A fix that wrote through to the backend but returned the freshly-defaulted object
    would show an operator ``unpinned`` on the very response to their edit, then ``pinned``
    on the next read — a discrepancy that reads as a race and is not one.
    """
    reg, _ = await _distributed()

    cfg = await reg.replace_device("dev1", base_url="http://dev1", rate_limit_rps=7, keep_auth=True)

    assert cfg.fingerprint_state == fp.STATE_PINNED
    assert cfg.tls_spki_sha256 == SPKI_A


@pytest.mark.asyncio
async def test_a_credential_change_does_not_unpin_the_device():
    """A new credential is not evidence about a TLS key.

    This is the path that carries `keep_auth=False`, and it is the one the lab took while
    migrating a device to a `secret://` reference — an operation about *authentication* that
    silently reset what the gateway *trusts*.
    """
    reg, backend = await _distributed(auth=ApiKeyAuth(api_key="old", location="header", header_name="X-API-Key"))

    await reg.replace_device(
        "dev1",
        base_url="http://dev1",
        auth=ApiKeyAuth(api_key="new", location="header", header_name="X-API-Key"),
        keep_auth=False,
    )

    after = await backend.get_device("dev1")
    assert after.fingerprint_state == fp.STATE_PINNED
    assert after.tls_spki_sha256 == SPKI_A


@pytest.mark.asyncio
async def test_a_pending_approval_is_not_cleared_by_an_edit():
    """An unapproved key change is a decision in progress; an edit must not launder it.

    The restore path refuses to do this (``test_a_quarantined_device_comes_back
    _quarantined``). An update must refuse for the same reason: a quarantine cleared by a
    rate-limit change is a quarantine anyone with ``devices:write`` can lift without
    approving anything.
    """
    reg, backend = await _distributed(state=fp.STATE_PENDING, pending_tls_spki_sha256=SPKI_B)

    await reg.replace_device("dev1", base_url="http://dev1", rate_limit_rps=7, keep_auth=True)

    after = await backend.get_device("dev1")
    assert after.fingerprint_state == fp.STATE_PENDING
    assert after.pending_tls_spki_sha256 == SPKI_B


@pytest.mark.asyncio
async def test_a_per_device_policy_survives_an_edit():
    """``enforce`` is a deliberate per-device decision, not a derived value.

    Losing it downgrades the device to whatever the fleet default happens to be — silently,
    and in the direction of trusting more.

    Deliberately set on an **unpinned** device, so this fails against a guard that asks only
    "is there a pin?". A device can carry a policy before it has ever been observed, and
    that is exactly the window where dropping the policy matters most.
    """
    reg, backend = await _distributed(spki=None, state=fp.STATE_UNPINNED, fingerprint_policy=fp.POLICY_ENFORCE)

    await reg.replace_device("dev1", base_url="http://dev1", rate_limit_rps=7, keep_auth=True)

    after = await backend.get_device("dev1")
    assert after.fingerprint_policy == fp.POLICY_ENFORCE


@pytest.mark.asyncio
async def test_the_pin_is_carried_even_when_the_base_url_changes():
    """Deliberate, and the opposite of what a "the endpoint changed, so reset it" reading
    would do.

    Repointing a device at a new URL is a trust change, and the designed way to accept one
    is the ``key_changed`` → approve flow (ADR-0015 §6): loud and audited. Resetting instead
    would be silent, and would leave "change the URL" as a way to launder a new key past the
    pin — a bypass available to anyone who can edit a device.
    """
    reg, backend = await _distributed()

    await reg.replace_device("dev1", base_url="https://somewhere-else.example:9443", keep_auth=True)

    after = await backend.get_device("dev1")
    assert after.base_url == "https://somewhere-else.example:9443"
    assert after.tls_spki_sha256 == SPKI_A, "the new endpoint must prove itself, not inherit trust"


@pytest.mark.asyncio
async def test_a_device_that_was_never_pinned_is_left_alone():
    """The guard, not an accident of the data.

    Without it every edit of every unpinned device would write a block of ``None``s back
    over itself — harmless but pure cost, on the most common path there is.
    """
    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    backend = MemoryRegistryBackend()
    reg = Registry(config={"mode": "distributed"}, backend=backend, codec=codec)
    await reg.register_device("dev1", "http://dev1")

    writes: list[tuple] = []
    original = backend.update_device_fields

    async def counting(hostname, **fields):
        writes.append((hostname, tuple(sorted(fields))))
        return await original(hostname, **fields)

    backend.update_device_fields = counting  # type: ignore[method-assign]
    await reg.replace_device("dev1", base_url="http://dev1", rate_limit_rps=7, keep_auth=True)

    assert not any("tls_spki_sha256" in fields for _, fields in writes)
    after = await backend.get_device("dev1")
    assert after.fingerprint_state == fp.STATE_UNPINNED


@pytest.mark.asyncio
async def test_the_pin_is_actually_persisted_not_just_set_on_the_object():
    """Storage and the returned object are two claims, and only one of them is the fix.

    Separated because the stock in-memory double conflates them (see ``_StoringBackend``):
    a fix that only mutated the record it hands back would leave the *stored* device
    unpinned, and the next read — the next health check — would re-TOFU it exactly as
    before, while the response to the operator's edit looked correct.
    """
    reg, backend = await _distributed()

    await reg.replace_device("dev1", base_url="http://dev1", rate_limit_rps=7, keep_auth=True)

    stored = await backend.get_device("dev1")
    assert stored.fingerprint_state == fp.STATE_PINNED
    assert stored.tls_spki_sha256 == SPKI_A
    assert stored.fingerprint_pinned_at == 1700000000.0


def test_a_trust_record_survives_the_redis_hash_encoding():
    """The other half of persistence: the wire format has to carry it.

    A trust record contains ``None``s — an empty pending slot, an absent policy — and the
    Redis hash has no null. ``update_device_fields`` writes ``""`` for them, so the parse
    has to map ``""`` back to ``None``; a round trip that produced the *string* ``"None"``
    would leave a device whose ``pending_tls_spki_sha256`` is the four characters N-o-n-e,
    which compares unequal to every real SPKI and equal to nothing — an endless mismatch.

    Tested against the real serializer rather than a Redis double, because it is the
    serializer that has to be right.
    """
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1", **_pinned_fields())
    hashed = cfg.to_redis_hash()

    assert all(isinstance(v, str) for v in hashed.values()), "a Redis hash holds strings"
    back = DeviceConfig.from_redis_hash(hashed)

    for field in fp.TRUST_FIELDS:
        assert getattr(back, field) == getattr(cfg, field), field
    assert back.pending_tls_spki_sha256 is None
    assert back.fingerprint_policy is None


# --- embedded: the same guarantee at the layer an operator touches ------------------


def _client(monkeypatch, tmp_path):
    # Per-client throwaway cwd: embedded persists to the RELATIVE "./data/devices.db", and
    # a leaked store loads on the next lifespan-entering test. See test_backup_restore.
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setenv("MCP_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("MCP_ALLOW_PRIVATE_TARGETS", "true")
    from device_mcp_gateway.main import create_app

    return TestClient(create_app())


def _auth():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def test_a_put_through_the_api_keeps_the_pin(monkeypatch, tmp_path):
    """End to end, because the route is where the operator's edit actually arrives.

    Registers with ``expected_tls_spki_sha256`` — ADR-0015 §8's out-of-band verification,
    the case with the most to lose, since that pin encodes a human having checked a key by
    hand and cannot be re-established by observation.
    """
    client = _client(monkeypatch, tmp_path)
    resp = client.post(
        "/v1/devices",
        headers=_auth(),
        json={"hostname": "alpha", "base_url": "https://127.0.0.1:9", "expected_tls_spki_sha256": SPKI_A},
    )
    assert resp.status_code in (200, 201), resp.text
    assert client.get("/v1/devices/alpha", headers=_auth()).json()["fingerprint_state"] == fp.STATE_PINNED

    assert client.put("/v1/devices/alpha", headers=_auth(), json={"rate_limit_rps": 7}).status_code == 200

    detail = client.get("/v1/devices/alpha", headers=_auth()).json()
    assert detail["rate_limit_rps"] == 7
    assert detail["fingerprint_state"] == fp.STATE_PINNED
    assert detail["tls_spki_sha256"] == SPKI_A


def test_the_put_response_itself_shows_the_pin(monkeypatch, tmp_path):
    """A console renders the mutation response. If that says ``unpinned``, the operator is
    told their edit unpinned the device even though a re-read would say otherwise."""
    client = _client(monkeypatch, tmp_path)
    client.post(
        "/v1/devices",
        headers=_auth(),
        json={"hostname": "alpha", "base_url": "https://127.0.0.1:9", "expected_tls_spki_sha256": SPKI_A},
    )

    body = client.put("/v1/devices/alpha", headers=_auth(), json={"rate_limit_rps": 7}).json()

    assert body["device"]["fingerprint_state"] == fp.STATE_PINNED
    assert body["device"]["tls_spki_sha256"] == SPKI_A


# --- the two field lists must not drift apart ---------------------------------------


def test_every_trust_field_is_also_archived():
    """The archive's fingerprint block is a superset of the trust record.

    Two lists of field names now describe overlapping things — what constitutes trust, and
    what a backup carries. A field added to the first and forgotten in the second would be
    preserved across an edit and lost across a restore, which is the kind of asymmetry
    nobody discovers until a restore quietly unpins something.
    """
    missing = set(fp.TRUST_FIELDS) - set(_FINGERPRINT_FIELDS)
    assert not missing, f"trust fields absent from the archive format: {sorted(missing)}"
