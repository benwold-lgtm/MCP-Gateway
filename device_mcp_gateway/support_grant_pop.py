# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7, Tier 1 — sender-constrained proof-of-possession.

Tier 0's bearer is a plain secret: whoever holds it can present it. Tier 1 asks for one more
thing, on every call, that the bearer alone does not prove — a signature over *this specific
request*, verifiable against a public key the operator submitted when the request was raised.
Stealing the bearer no longer suffices; the private key never travels with any request.

Ed25519 only — no algorithm negotiation, no per-deployment choice. One scheme this codebase
either verifies correctly or does not; a chooser is a second thing to get right for zero
benefit here (there is exactly one caller of this module, the gateway itself, deciding what it
accepts from an operator's own client — not a federation boundary where two parties need to
agree on a shared menu).

**No nonce cache.** Replay is closed by a strictly-increasing timestamp per grant instead: a
signed request's timestamp must be newer than the highest one this grant has ever presented
(`SupportGrantStore.check_proof`, alongside the ordinary liveness/revocation check) and within
a bounded window of the gateway's own clock. A captured signature is stale the moment a
fresher one is accepted, with no set to size or sweep — the same "state the store already
carries is enough, don't add a second store for a second kind of freshness" instinct as
`plan_token.py`'s age check.

This module is pure: it knows nothing about grants, storage, or HTTP. It signs nothing either
— only the operator's own client holds a private key; the gateway only ever verifies.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: Ed25519 public keys are exactly 32 raw bytes and signatures exactly 64 — fixed sizes are
#: part of the scheme, not a convention to configure, so a value of the wrong length is
#: rejected before it ever reaches the crypto library.
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64


class InvalidPublicKey(ValueError):
    """A submitted public key is not well-formed base64, or not 32 raw bytes."""


def parse_public_key(public_key_b64: str) -> bytes:
    """Validate a submitted public key's shape. Returns the raw bytes if well-formed —
    callers that only need the validity check can discard the return value."""
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except Exception as exc:
        raise InvalidPublicKey("public_key is not valid base64") from exc
    if len(raw) != _PUBLIC_KEY_BYTES:
        raise InvalidPublicKey(f"public_key must decode to exactly {_PUBLIC_KEY_BYTES} bytes")
    return raw


def signing_message(*, method: str, path_and_query: str, timestamp: str) -> bytes:
    """The canonical bytes a signature covers — the request-target, not the body. A tampered
    method or path invalidates the signature; the body is already covered by TLS + whatever
    the route itself validates, and is not this mechanism's job to protect a second time."""
    return f"{method.upper()}\n{path_and_query}\n{timestamp}".encode()


def verify_signature(*, public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """True iff `signature_b64` is a valid Ed25519 signature of `message` under
    `public_key_b64`. Never raises for a malformed key or signature — either is simply not
    valid, the same posture as a bad bearer token."""
    try:
        raw_key = parse_public_key(public_key_b64)
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:  # noqa: BLE001 — a malformed key/signature is simply not valid
        return False
    if len(signature) != _SIGNATURE_BYTES:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False
