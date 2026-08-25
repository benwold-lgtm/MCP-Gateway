# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 §6, implementation note 2026-08-24 — the HMAC-signed plan token.

``plan_digest`` (a bare SHA-256) has no age; the 7-day validity window needs
somewhere to live without the gateway persisting a plan. This is the
stateless-signed-token half of that: mint at dry-run time, verify at apply
time, reject on either a bad signature or an expired timestamp — and keep the
two distinguishable, since ADR-0018 §6 gives them different meanings
(``ERR_PLAN_STALE``'s "legitimate drift" vs. "replayed/guessed" causes).
"""

from __future__ import annotations

import hashlib

import pytest

from device_mcp_gateway.shared.plan_token import (
    InvalidPlanToken,
    PlanTokenExpired,
    derive_plan_token_keys,
    mint_plan_token,
    verify_plan_token,
)

_DIGEST_A = hashlib.sha256(b"plan-a").hexdigest()
_DIGEST_B = hashlib.sha256(b"plan-b").hexdigest()


@pytest.fixture
def keys():
    return derive_plan_token_keys(["z" * 44])  # a plausible-shaped Fernet key string


def test_roundtrip_recovers_the_digest_and_timestamp(keys):
    token = mint_plan_token(_DIGEST_A, keys=keys, now=1_000_000)
    payload = verify_plan_token(token, keys=keys, max_age_seconds=7 * 86400, now=1_000_100)
    assert payload.digest == _DIGEST_A
    assert payload.issued_at == 1_000_000


def test_a_tampered_token_does_not_verify(keys):
    token = mint_plan_token(_DIGEST_A, keys=keys, now=1_000_000)
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]
    with pytest.raises(InvalidPlanToken):
        verify_plan_token(tampered, keys=keys, max_age_seconds=7 * 86400, now=1_000_100)


def test_a_token_for_a_different_digest_does_not_collide(keys):
    token = mint_plan_token(_DIGEST_A, keys=keys, now=1_000_000)
    payload = verify_plan_token(token, keys=keys, max_age_seconds=7 * 86400, now=1_000_100)
    assert payload.digest != _DIGEST_B


def test_within_the_validity_window_verifies(keys):
    token = mint_plan_token(_DIGEST_A, keys=keys, now=0)
    verify_plan_token(token, keys=keys, max_age_seconds=7 * 86400, now=7 * 86400 - 1)


def test_past_the_validity_window_is_expired_not_invalid(keys):
    token = mint_plan_token(_DIGEST_A, keys=keys, now=0)
    with pytest.raises(PlanTokenExpired) as excinfo:
        verify_plan_token(token, keys=keys, max_age_seconds=7 * 86400, now=7 * 86400 + 1)
    assert excinfo.value.issued_at == 0
    assert excinfo.value.max_age_seconds == 7 * 86400


def test_a_backdated_token_is_rejected_not_treated_as_fresh(keys):
    # Minting can't be forced to backdate through the public API, but a token whose
    # issued_at claims to be far in the future relative to "now" (clock skew beyond the
    # small slack, or a forged timestamp under a *stolen* key) must not verify as valid —
    # only genuine, bounded clock skew is tolerated.
    token = mint_plan_token(_DIGEST_A, keys=keys, now=1_000_000)
    with pytest.raises(PlanTokenExpired):
        verify_plan_token(token, keys=keys, max_age_seconds=7 * 86400, now=1_000_000 - 3600)


def test_malformed_base64_is_invalid_not_a_crash(keys):
    with pytest.raises(InvalidPlanToken):
        verify_plan_token("not-valid-base64!!!", keys=keys, max_age_seconds=7 * 86400)


def test_wrong_length_payload_is_invalid(keys):
    import base64

    short = base64.urlsafe_b64encode(b"too-short").decode().rstrip("=")
    with pytest.raises(InvalidPlanToken):
        verify_plan_token(short, keys=keys, max_age_seconds=7 * 86400)


def test_rotation_the_old_key_still_verifies_what_it_signed():
    old_key = derive_plan_token_keys(["old-key-material-000000000000000000000"])
    new_key = derive_plan_token_keys(["new-key-material-111111111111111111111"])
    token = mint_plan_token(_DIGEST_A, keys=old_key, now=1_000_000)

    # Deployed with [new, old] during a rotation window, newest first.
    both = new_key + old_key
    payload = verify_plan_token(token, keys=both, max_age_seconds=7 * 86400, now=1_000_100)
    assert payload.digest == _DIGEST_A


def test_rotation_a_token_signed_under_the_retired_key_fails_once_it_is_dropped():
    old_key = derive_plan_token_keys(["old-key-material-000000000000000000000"])
    new_key = derive_plan_token_keys(["new-key-material-111111111111111111111"])
    token = mint_plan_token(_DIGEST_A, keys=old_key, now=1_000_000)

    with pytest.raises(InvalidPlanToken):
        verify_plan_token(token, keys=new_key, max_age_seconds=7 * 86400, now=1_000_100)


def test_minting_uses_the_primary_first_key():
    old_key = derive_plan_token_keys(["old-key-material-000000000000000000000"])
    new_key = derive_plan_token_keys(["new-key-material-111111111111111111111"])
    token = mint_plan_token(_DIGEST_A, keys=new_key + old_key, now=1_000_000)

    # Verifies under the new key alone -> it was signed with the primary (first) key.
    verify_plan_token(token, keys=new_key, max_age_seconds=7 * 86400, now=1_000_100)
    with pytest.raises(InvalidPlanToken):
        verify_plan_token(token, keys=old_key, max_age_seconds=7 * 86400, now=1_000_100)


def test_different_secret_keys_derive_different_hmac_keys():
    a = derive_plan_token_keys(["key-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
    b = derive_plan_token_keys(["key-two-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"])
    assert a != b


def test_minting_rejects_a_malformed_digest(keys):
    with pytest.raises(ValueError):
        mint_plan_token("not-a-hex-digest", keys=keys)


def test_minting_with_no_keys_raises():
    with pytest.raises(ValueError):
        mint_plan_token(_DIGEST_A, keys=[])


def test_verifying_with_no_keys_raises_invalid_not_expired():
    with pytest.raises(InvalidPlanToken):
        verify_plan_token("anything", keys=[], max_age_seconds=7 * 86400)
