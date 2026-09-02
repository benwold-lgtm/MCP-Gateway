"""A PUT must not accept a field it silently drops (LR-57 / L-8).

``POST /v1/devices`` applies ``expected_tls_spki_sha256`` and ``fingerprint_policy``.
``PUT /v1/devices/{h}`` parsed **neither**, so a request carrying either returned 200 with
nothing changed. Not a 400 — a success, reporting an outcome that had not happened.

That is LR-48's shape in mirror image. LR-48 was a key the gateway *refused* where the
caller thought it was required; this is a key the gateway *takes and drops*. Both are a
contract disagreement that no status code reveals, and this one is the worse of the two: a
refusal is at least visible at the moment of the mistake.

The two fields get opposite answers, and the asymmetry is the point.

* ``fingerprint_policy`` is **policy**, not evidence. Moving a device from ``warn`` to
  ``enforce`` is an ordinary operation, and until now the only way to do it was to delete
  the device and register it again — for a *tightening* of a security control, which is a
  cost paid in exactly the wrong direction. It is now honoured, audited, and clearable.

* ``expected_tls_spki_sha256`` is **trust**, and it is refused. Writing it here would be a
  quieter version of the laundering path ``_carry_fingerprint`` already refuses to open:
  set the new key first and the probe that would have raised ``key_changed`` instead finds
  agreement and says nothing.

Route-level throughout. The defect was that the *handler* ignored two keys, so a test below
the route could not have seen it — and every field here is applied after ``replace_device``
rather than through it.
"""

from __future__ import annotations

import itertools

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from device_mcp_gateway.security import fingerprint as fp

SPKI_A = "a" * 64
SPKI_B = "b" * 64
ADMIN_KEY = "test-admin-key"
_STACK_SEQ = itertools.count()


@pytest.fixture()
def client(monkeypatch, tmp_path):
    # Per-client throwaway cwd: embedded persists to the RELATIVE "./data/devices.db", and a
    # leaked store loads on the next lifespan-entering test.
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


def _register(client, hostname="alpha", **extra):
    body = {"hostname": hostname, "base_url": "https://127.0.0.1:9", **extra}
    resp = client.post("/v1/devices", headers=_auth(), json=body)
    assert resp.status_code in (200, 201), resp.text
    return resp


def _detail(client, hostname="alpha"):
    resp = client.get(f"/v1/devices/{hostname}", headers=_auth())
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- fingerprint_policy: honoured -----------------------------------------------------


def test_an_update_can_tighten_the_policy(client):
    """The operation the gap made impossible without deleting the device."""
    _register(client)
    assert _detail(client)["fingerprint_policy"] is None

    resp = client.put("/v1/devices/alpha", headers=_auth(), json={"fingerprint_policy": "enforce"})

    assert resp.status_code == 200, resp.text
    assert _detail(client)["fingerprint_policy"] == fp.POLICY_ENFORCE


def test_the_response_body_shows_the_new_policy(client):
    """A console renders the mutation response. Reporting the pre-update value would say the
    edit did nothing — the same false report this whole file is about, moved one layer out."""
    _register(client)

    body = client.put("/v1/devices/alpha", headers=_auth(), json={"fingerprint_policy": "enforce"}).json()

    assert body["device"]["fingerprint_policy"] == fp.POLICY_ENFORCE


def test_an_explicit_null_clears_the_override(client):
    """Otherwise `enforce` is a value you can set and never remove.

    That is the same trap as a spec URL the form shows but cannot clear: an operator who
    tries a per-device override is stuck with it, and the only exit is deleting the device.
    Clearing restores inheritance from `security.fingerprint_policy`, which is a real state
    and not the same as `warn`.
    """
    _register(client, fingerprint_policy="enforce")
    assert _detail(client)["fingerprint_policy"] == fp.POLICY_ENFORCE

    resp = client.put("/v1/devices/alpha", headers=_auth(), json={"fingerprint_policy": None})

    assert resp.status_code == 200, resp.text
    assert _detail(client)["fingerprint_policy"] is None


def test_an_unrelated_edit_still_leaves_the_policy_alone(client):
    """Presence, not truthiness. An absent key and an explicit null are different requests,
    and collapsing them would make every rate-limit change clear the override — reintroducing
    the ADR-0015 carry-forward bug through the door built to fix its sibling."""
    _register(client, fingerprint_policy="enforce")

    assert client.put("/v1/devices/alpha", headers=_auth(), json={"rate_limit_rps": 7}).status_code == 200

    detail = _detail(client)
    assert detail["rate_limit_rps"] == 7
    assert detail["fingerprint_policy"] == fp.POLICY_ENFORCE


def test_a_bad_policy_is_refused_and_changes_nothing(client):
    """Refused *before* the write (LR-51's rule), so the device is not left half-edited."""
    _register(client, fingerprint_policy="enforce")

    resp = client.put(
        "/v1/devices/alpha",
        headers=_auth(),
        json={"rate_limit_rps": 7, "fingerprint_policy": "paranoid"},
    )

    assert resp.status_code == 400
    assert "warn" in resp.json()["detail"] and "enforce" in resp.json()["detail"]
    detail = _detail(client)
    assert detail["fingerprint_policy"] == fp.POLICY_ENFORCE
    assert detail["rate_limit_rps"] is None, "a refused update must not apply its other fields"


# --- expected_tls_spki_sha256: refused ------------------------------------------------


def test_an_update_may_not_set_the_pin(client):
    """The refusal that replaces the silent no-op."""
    _register(client)

    resp = client.put("/v1/devices/alpha", headers=_auth(), json={"expected_tls_spki_sha256": SPKI_A})

    assert resp.status_code == 400, resp.text
    assert _detail(client)["tls_spki_sha256"] is None


def test_the_refusal_names_both_ways_to_actually_do_it(client):
    """A 400 that only says no leaves the operator where the silent 200 did — with a thing
    they need to do and no way to. Registration closes the trust-on-first-use window;
    approval accepts a key the device is presenting now. The message names both."""
    _register(client)

    detail = client.put("/v1/devices/alpha", headers=_auth(), json={"expected_tls_spki_sha256": SPKI_A}).json()[
        "detail"
    ]

    assert "registering" in detail
    assert "fingerprint/approve" in detail


def test_an_update_may_not_overwrite_an_existing_pin(client):
    """The reason this is a refusal rather than a feature.

    A PUT-writable pin is a quieter version of the bypass `_carry_fingerprint` documents:
    write the key the attacker's endpoint presents, and the probe that would have raised
    `key_changed` finds agreement instead. No verdict, no quarantine, no audit line saying a
    trust decision was made.
    """
    _register(client, expected_tls_spki_sha256=SPKI_A)
    assert _detail(client)["fingerprint_state"] == fp.STATE_PINNED

    resp = client.put("/v1/devices/alpha", headers=_auth(), json={"expected_tls_spki_sha256": SPKI_B})

    assert resp.status_code == 400
    assert _detail(client)["tls_spki_sha256"] == SPKI_A


def test_the_pin_refusal_happens_before_anything_is_written(client):
    """LR-51 again: a refusal the gateway has already half-carried-out is worse than either
    outcome, because the corrected retry then collides with a change nobody was told about."""
    _register(client)

    resp = client.put(
        "/v1/devices/alpha",
        headers=_auth(),
        json={"rate_limit_rps": 7, "expected_tls_spki_sha256": SPKI_A},
    )

    assert resp.status_code == 400
    assert _detail(client)["rate_limit_rps"] is None


def test_registration_still_accepts_the_pin(client):
    """The guard against fixing this by refusing the field everywhere. Registration is where
    the pre-pin does its work — supplied there it closes the TOFU window outright."""
    _register(client, hostname="beta", expected_tls_spki_sha256=SPKI_A)

    detail = _detail(client, "beta")
    assert detail["tls_spki_sha256"] == SPKI_A
    assert detail["fingerprint_state"] == fp.STATE_PINNED
