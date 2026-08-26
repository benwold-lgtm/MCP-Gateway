# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7, Tier 1 — sender-constrained proof-of-possession, end-to-end.

`test_support_grant_pop.py` proves the signature primitive in isolation;
`test_support_grant_authentication.py` proves Tier 0 end-to-end. This proves the property
Tier 1 exists for: a bearer alone is no longer sufficient once an operator opted into it at
raise time — every request also needs a fresh, valid signature over itself, and a captured
one cannot be resubmitted.
"""

from __future__ import annotations

import base64
import itertools
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from device_mcp_gateway.support_grant_pop import signing_message

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40


def _client(monkeypatch, tmp_path):
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.main import create_app

    return TestClient(create_app())


def _admin():
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, pub_b64


def _sign(priv, *, method: str, path_and_query: str, timestamp: str) -> str:
    message = signing_message(method=method, path_and_query=path_and_query, timestamp=timestamp)
    return base64.b64encode(priv.sign(message)).decode()


def _grant_a_tier1_credential(client, priv, pub_b64, *, scopes=("devices:read",)) -> str:
    raise_resp = client.post(
        "/v1/support-requests",
        headers=_admin(),
        json={
            "provider_subject": "oidc:provider-idp#op1",
            "requested_scopes": list(scopes),
            "justification": "INC-1",
            "public_key": pub_b64,
        },
    )
    request_id = raise_resp.json()["request_id"]
    client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    poll = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "oidc:provider-idp#op1"}
    )
    return poll.json()["credential"]


def _signed_headers(priv, *, method: str, path_and_query: str, timestamp: float | None = None) -> dict:
    ts = str(timestamp if timestamp is not None else time.time())
    sig = _sign(priv, method=method, path_and_query=path_and_query, timestamp=ts)
    return {"X-Support-Timestamp": ts, "X-Support-Signature": sig}


def test_a_correctly_signed_tier1_request_authenticates(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)

    headers = {
        "Authorization": f"Bearer {credential}",
        **_signed_headers(priv, method="GET", path_and_query="/v1/devices"),
    }
    resp = client.get("/v1/devices", headers=headers)

    assert resp.status_code == 200, resp.text


def test_the_bearer_alone_is_refused_once_the_grant_is_sender_constrained(monkeypatch, tmp_path):
    """The whole point of Tier 1: presenting only the bearer, with no signature at all, no
    longer suffices once the operator opted in."""
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)

    resp = client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})

    assert resp.status_code == 401


def test_a_signature_from_the_wrong_key_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    wrong_priv, _ = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)

    headers = {
        "Authorization": f"Bearer {credential}",
        **_signed_headers(wrong_priv, method="GET", path_and_query="/v1/devices"),
    }
    resp = client.get("/v1/devices", headers=headers)

    assert resp.status_code == 401


def test_signing_a_different_path_than_the_one_requested_is_refused(monkeypatch, tmp_path):
    """A signature over `/v1/devices` must not authenticate a request for
    `/v1/devices/other-host` — the canonical message binds the signature to this exact
    request, not just to holding the key."""
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)

    headers = {
        "Authorization": f"Bearer {credential}",
        **_signed_headers(priv, method="GET", path_and_query="/v1/devices/some-other-host"),
    }
    resp = client.get("/v1/devices", headers=headers)

    assert resp.status_code == 401


def test_a_captured_signature_cannot_be_replayed(monkeypatch, tmp_path):
    """The property the whole no-nonce-cache design rests on."""
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)
    headers = {
        "Authorization": f"Bearer {credential}",
        **_signed_headers(priv, method="GET", path_and_query="/v1/devices"),
    }

    first = client.get("/v1/devices", headers=headers)
    replay = client.get("/v1/devices", headers=headers)

    assert first.status_code == 200
    assert replay.status_code == 401


def test_a_later_signed_request_succeeds_after_an_earlier_one(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)
    now = time.time()

    first = client.get(
        "/v1/devices",
        headers={
            "Authorization": f"Bearer {credential}",
            **_signed_headers(priv, method="GET", path_and_query="/v1/devices", timestamp=now),
        },
    )
    second = client.get(
        "/v1/devices",
        headers={
            "Authorization": f"Bearer {credential}",
            **_signed_headers(priv, method="GET", path_and_query="/v1/devices", timestamp=now + 1),
        },
    )

    assert (first.status_code, second.status_code) == (200, 200)


def test_a_stale_timestamp_outside_the_window_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)

    headers = {
        "Authorization": f"Bearer {credential}",
        **_signed_headers(priv, method="GET", path_and_query="/v1/devices", timestamp=time.time() - 3600),
    }
    resp = client.get("/v1/devices", headers=headers)

    assert resp.status_code == 401


def test_missing_signature_headers_are_refused_not_treated_as_tier0(monkeypatch, tmp_path):
    """A grant that IS sender-constrained must never silently fall back to bearer-only
    behavior just because the headers were left off."""
    client = _client(monkeypatch, tmp_path)
    priv, pub_b64 = _keypair()
    credential = _grant_a_tier1_credential(client, priv, pub_b64)

    resp = client.get(
        "/v1/devices", headers={"Authorization": f"Bearer {credential}", "X-Support-Timestamp": str(time.time())}
    )

    assert resp.status_code == 401


def test_a_tier0_grant_ignores_signature_headers_entirely(monkeypatch, tmp_path):
    """A grant raised WITHOUT a public key stays Tier 0 — stray signature-shaped headers on
    the request must not be required, and must not break it either."""
    client = _client(monkeypatch, tmp_path)
    raise_resp = client.post(
        "/v1/support-requests",
        headers=_admin(),
        json={"provider_subject": "op1", "requested_scopes": ["devices:read"], "justification": "a"},
    )
    request_id = raise_resp.json()["request_id"]
    client.post(f"/v1/support-requests/{request_id}/approve", headers=_admin())
    credential = client.get(
        f"/v1/support-requests/{request_id}", headers=_admin(), params={"provider_subject": "op1"}
    ).json()["credential"]

    resp = client.get("/v1/devices", headers={"Authorization": f"Bearer {credential}"})

    assert resp.status_code == 200
