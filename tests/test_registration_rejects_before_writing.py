"""A refused registration must not leave a device behind (ADR-0015 §8).

**Found by tracing the claim flow end to end, not by a suite.** `_apply_register` validates
`expected_tls_spki_sha256` and `fingerprint_policy` *after* `reg.register_device` has already
written the device and started its pod. Both raise 400. So a caller who fumbles either field
gets a refusal for a registration that in fact happened.

Three things go wrong at once, which is why this is a security bug and not a rough edge:

* The device is live and **unpinned**. Pre-pinning exists precisely so there is "no TOFU
  window at all" (the comment above the code that does it) — and this path opens exactly
  that window on a device whose operator asked, in the same request, to close it.
* `audit_request("device.create", ...)` sits *below* both raises, so the registration that
  succeeded is **never audited**. A device exists on the stack with no create record.
* The retry does not work. Correcting the digest and resubmitting hits
  `409 Device already registered`, and PUT handles neither field, so the pin cannot be
  established afterwards at all — the operator must delete and start over, having been told
  their registration failed.

The realistic trigger is not a typo. `openssl x509 -noout -fingerprint -sha256` prints
`AB:CD:EF:...` — colon-separated and upper case — and the console's claim form (ADR-0020 §4)
posts that field as free text with no client-side check.

`_apply_update` is the control: it validates everything before `replace_device`. The two were
deliberately split from one path (ADR-0022 slice 5) "without a second copy of the gates to
drift from this one" — and then drifted, in the direction that writes.
"""

from __future__ import annotations

import itertools

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ADMIN_KEY = "test-admin-key"
GOOD_SPKI = "a" * 64
_STACK_SEQ = itertools.count()


def _client(monkeypatch, tmp_path):
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


#: Every one of these is a plausible paste, not a fuzz input. The colon form is what
#: `openssl x509 -fingerprint` actually prints; the prefixed form is what a certificate
#: viewer copies; the short one is a digest missing a character.
@pytest.mark.parametrize(
    "bad_spki",
    [
        pytest.param(":".join("ab" for _ in range(32)).upper(), id="openssl-colon-form"),
        pytest.param("sha256:" + GOOD_SPKI, id="prefixed"),
        pytest.param("a" * 63, id="one-char-short"),
        pytest.param("z" * 64, id="not-hex"),
    ],
)
def test_a_refused_spki_registers_nothing(monkeypatch, tmp_path, bad_spki):
    client = _client(monkeypatch, tmp_path)
    resp = client.post(
        "/v1/devices",
        headers=_auth(),
        json={"hostname": "alpha", "base_url": "https://127.0.0.1:9", "expected_tls_spki_sha256": bad_spki},
    )
    assert resp.status_code == 400, resp.text

    # The refusal has to be true. A 200 here means the gateway said "no" and did it anyway.
    assert client.get("/v1/devices/alpha", headers=_auth()).status_code == 404


def test_a_refused_policy_registers_nothing(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post(
        "/v1/devices",
        headers=_auth(),
        json={"hostname": "alpha", "base_url": "https://127.0.0.1:9", "fingerprint_policy": "paranoid"},
    )
    assert resp.status_code == 400, resp.text
    assert client.get("/v1/devices/alpha", headers=_auth()).status_code == 404


def test_correcting_the_digest_and_retrying_works(monkeypatch, tmp_path):
    """The operator-facing consequence, stated as its own property.

    Fixing what the error message complained about and sending it again must register the
    device — pinned. Today the retry is refused as a duplicate of a device the operator was
    told did not get created, and the pin can never be set.
    """
    client = _client(monkeypatch, tmp_path)
    body = {"hostname": "alpha", "base_url": "https://127.0.0.1:9"}
    assert (
        client.post("/v1/devices", headers=_auth(), json={**body, "expected_tls_spki_sha256": "nope"}).status_code
        == 400
    )

    retry = client.post("/v1/devices", headers=_auth(), json={**body, "expected_tls_spki_sha256": GOOD_SPKI})
    assert retry.status_code in (200, 201), retry.text

    from device_mcp_gateway.security import fingerprint as fp

    detail = client.get("/v1/devices/alpha", headers=_auth()).json()
    assert detail["fingerprint_state"] == fp.STATE_PINNED
    assert detail["tls_spki_sha256"] == GOOD_SPKI
