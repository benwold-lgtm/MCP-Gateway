# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7, Tier 1 — the pure signature-verification primitive, in isolation.

No grant, no store, no HTTP involved yet — just: does a signature verify against a public
key over the exact bytes it claims to cover, and does tampering with any of method/path/
timestamp/key/signature invalidate it. The end-to-end proof-of-possession flow (raise with a
public key, approve, sign a real request) is `test_support_grant_pop_authentication.py`.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from device_mcp_gateway.support_grant_pop import (
    InvalidPublicKey,
    parse_public_key,
    signing_message,
    verify_signature,
)


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, pub_b64


def _sign(priv, message: bytes) -> str:
    return base64.b64encode(priv.sign(message)).decode()


# --- parse_public_key ------------------------------------------------------------------


def test_a_valid_ed25519_public_key_parses():
    _, pub_b64 = _keypair()
    raw = parse_public_key(pub_b64)
    assert len(raw) == 32


def test_malformed_base64_is_rejected():
    with pytest.raises(InvalidPublicKey):
        parse_public_key("not-valid-base64!!!")


def test_wrong_length_is_rejected():
    with pytest.raises(InvalidPublicKey):
        parse_public_key(base64.b64encode(b"too short").decode())


# --- verify_signature -------------------------------------------------------------------


def test_a_correctly_signed_message_verifies():
    priv, pub_b64 = _keypair()
    message = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    sig = _sign(priv, message)

    assert verify_signature(public_key_b64=pub_b64, message=message, signature_b64=sig) is True


def test_a_signature_from_a_different_key_does_not_verify():
    priv1, _ = _keypair()
    _, pub2_b64 = _keypair()
    message = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    sig = _sign(priv1, message)

    assert verify_signature(public_key_b64=pub2_b64, message=message, signature_b64=sig) is False


def test_tampering_with_the_method_invalidates_the_signature():
    priv, pub_b64 = _keypair()
    signed = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    sig = _sign(priv, signed)
    tampered = signing_message(method="POST", path_and_query="/v1/devices", timestamp="1000.5")

    assert verify_signature(public_key_b64=pub_b64, message=tampered, signature_b64=sig) is False


def test_tampering_with_the_path_invalidates_the_signature():
    priv, pub_b64 = _keypair()
    signed = signing_message(method="GET", path_and_query="/v1/devices/a", timestamp="1000.5")
    sig = _sign(priv, signed)
    tampered = signing_message(method="GET", path_and_query="/v1/devices/b", timestamp="1000.5")

    assert verify_signature(public_key_b64=pub_b64, message=tampered, signature_b64=sig) is False


def test_tampering_with_the_timestamp_invalidates_the_signature():
    priv, pub_b64 = _keypair()
    signed = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    sig = _sign(priv, signed)
    tampered = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.6")

    assert verify_signature(public_key_b64=pub_b64, message=tampered, signature_b64=sig) is False


def test_a_malformed_public_key_fails_closed_not_raises():
    message = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    assert verify_signature(public_key_b64="garbage", message=message, signature_b64="alsogarbage") is False


def test_a_malformed_signature_fails_closed_not_raises():
    _, pub_b64 = _keypair()
    message = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    assert verify_signature(public_key_b64=pub_b64, message=message, signature_b64="not-valid-base64!!!") is False


def test_a_signature_of_the_wrong_length_is_rejected():
    _, pub_b64 = _keypair()
    message = signing_message(method="GET", path_and_query="/v1/devices", timestamp="1000.5")
    short_sig = base64.b64encode(b"too short").decode()
    assert verify_signature(public_key_b64=pub_b64, message=message, signature_b64=short_sig) is False
