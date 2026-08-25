# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The plan-digest token (ADR-0018 §6, implementation note 2026-08-24).

§6 fixes ``plan_digest`` as a bare hex SHA-256, then separately gives it a
7-day validity window (Open questions, resolved 2026-08-21). A bare digest
carries no age, so the two cannot both hold unless something else carries the
timestamp. The shape settled on: a stateless, HMAC-signed token binding
``digest || issued_at`` — unforgeable, expiry-enforceable, and requiring the
gateway to persist nothing (the "gateway persists no plan" property §6 argues
for stays intact).

``plan_digest`` remains the literal SHA-256 hex string — human-legible, and
what goes in the audit record. ``plan_token`` is the opaque value the dry-run
response returns and the apply request must submit; verifying it recovers the
digest it was minted over and rejects it once ``max_age_seconds`` has passed.

This module knows nothing about restore, on_conflict, or archives — it signs
and verifies an already-computed digest string. That is deliberate: ADR-0022
reuses ADR-0018's canonicalization/digest mechanism for a different kind of
plan, and nothing here should assume the shape of a restore request.
"""

from __future__ import annotations

import base64
import hmac
import struct
import time
from dataclasses import dataclass

__all__ = [
    "InvalidPlanToken",
    "PlanTokenExpired",
    "PlanTokenPayload",
    "derive_plan_token_keys",
    "mint_plan_token",
    "verify_plan_token",
]

_DOMAIN = b"mcp-gateway-plan-token-v1"
_DIGEST_BYTES = 32  # SHA-256 hex is 64 chars / 32 raw bytes
_TIMESTAMP_STRUCT = struct.Struct(">Q")  # unsigned 8-byte big-endian unix seconds
_TAG_BYTES = 32  # HMAC-SHA256 output


class InvalidPlanToken(ValueError):
    """The token is malformed, or does not verify under any configured key."""


class PlanTokenExpired(ValueError):
    """The token verifies, but its ``issued_at`` is older than the allowed window."""

    def __init__(self, issued_at: int, max_age_seconds: int):
        self.issued_at = issued_at
        self.max_age_seconds = max_age_seconds
        super().__init__(f"plan token issued at {issued_at} exceeds the {max_age_seconds}s validity window")


@dataclass(frozen=True)
class PlanTokenPayload:
    digest: str
    issued_at: int


def derive_plan_token_keys(secret_keys: list[str]) -> list[bytes]:
    """Derive one HMAC key per configured Fernet key, via HKDF-SHA256.

    Reuses the operator-provisioned ``MCP_SECRET_KEY`` / ``gateway.secret_keys``
    material rather than requiring a second secret to provision — but derives a
    domain-separated subkey rather than using the Fernet key directly, so
    signing plan tokens is not silently coupled to credential-encryption key
    rotation (a Fernet key and an HMAC key are different key *types*, and
    ``MultiFernet``'s rotation semantics were designed for one, not both).

    Order is preserved (first key primary, for minting); every derived key is
    tried on verification, giving plan tokens the same zero-downtime rotation
    window ``CredentialCodec`` gives credential ciphertext.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    derived = []
    for key in secret_keys:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_DOMAIN)
        derived.append(hkdf.derive(key.encode()))
    return derived


def mint_plan_token(digest_hex: str, *, keys: list[bytes], now: int | None = None) -> str:
    """Sign ``digest_hex`` (a plan_digest string) under the primary (first) key.

    Returns a URL-safe base64 token carrying ``digest || issued_at || hmac_tag``.
    """
    if not keys:
        raise ValueError("no plan-token signing key configured")
    digest_bytes = bytes.fromhex(digest_hex)
    if len(digest_bytes) != _DIGEST_BYTES:
        raise ValueError(f"plan_digest must be a {_DIGEST_BYTES * 2}-char hex SHA-256, got {digest_hex!r}")
    issued_at = int(now if now is not None else time.time())
    body = digest_bytes + _TIMESTAMP_STRUCT.pack(issued_at)
    tag = hmac.new(keys[0], body, "sha256").digest()
    return base64.urlsafe_b64encode(body + tag).decode("ascii").rstrip("=")


def verify_plan_token(
    token: str,
    *,
    keys: list[bytes],
    max_age_seconds: int,
    now: int | None = None,
) -> PlanTokenPayload:
    """Verify a token's signature and age, returning the digest/issued_at it carries.

    Every configured key is tried (rotation window), not only the primary —
    mirroring how ``CredentialCodec`` decrypts with any key while encrypting
    only with the first. Raises :class:`InvalidPlanToken` for a malformed or
    unsigned-by-any-configured-key token, and :class:`PlanTokenExpired`
    separately, so a caller can tell "forged/replayed from elsewhere" apart
    from "legitimately stale" (ADR-0018 §6, ``ERR_PLAN_STALE``'s two causes).
    """
    if not keys:
        raise InvalidPlanToken("no plan-token verification key configured")
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # malformed base64
        raise InvalidPlanToken("plan token is not valid base64") from exc

    expected_len = _DIGEST_BYTES + _TIMESTAMP_STRUCT.size + _TAG_BYTES
    if len(raw) != expected_len:
        raise InvalidPlanToken(f"plan token has the wrong length ({len(raw)}, expected {expected_len})")

    body, tag = raw[:-_TAG_BYTES], raw[-_TAG_BYTES:]
    digest_bytes, (issued_at,) = body[:_DIGEST_BYTES], _TIMESTAMP_STRUCT.unpack(body[_DIGEST_BYTES:])

    if not any(hmac.compare_digest(hmac.new(k, body, "sha256").digest(), tag) for k in keys):
        raise InvalidPlanToken("plan token signature does not verify under any configured key")

    age = int(now if now is not None else time.time()) - issued_at
    if age > max_age_seconds or age < -60:  # small slack for clock skew, not for backdating
        raise PlanTokenExpired(issued_at, max_age_seconds)

    return PlanTokenPayload(digest=digest_bytes.hex(), issued_at=issued_at)
