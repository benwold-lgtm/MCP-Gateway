"""A restore plan token must not be minted under a key only one replica holds.

`_plan_token_keys` fell back to a **process-local** HMAC key whenever no `MCP_SECRET_KEY` was
configured. Its comment claimed distributed mode could not reach that fallback, because that
mode "refuses to start without a key, so this path is unreachable there".

It is reachable. `main.py`'s refusal is gated on `and not allow_plaintext_credentials` — an
override the refusal's own error text advertises. Under it, a distributed stack starts with no
key, and every replica mints plan tokens under a different one.

The operator-visible result is the part that matters: preview lands on replica A, apply is
load-balanced to replica B, and B answers `ERR_PLAN_STALE` — *"Preview again and submit the
plan_token from that preview."* Doing exactly that fails again, on `(N-1)/N` of attempts,
forever. The advice is correct for every legitimate cause of that error and useless for this
one, and nothing anywhere names the real reason. A secure mechanism no correct operator
behaviour can complete is one that gets worked around.

So the refusal moves to preview, where the cause can still be named. Embedded mode keeps the
fallback: there is one process, and "preview again" genuinely is the whole cost of a restart.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from device_mcp_gateway.api.backup import _plan_token_keys


def test_distributed_without_a_key_refuses_rather_than_minting_a_local_one():
    with pytest.raises(HTTPException) as exc:
        _plan_token_keys({"registry": {"mode": "distributed"}})
    assert exc.value.status_code == 503
    # The message has to name the cause, not the symptom — that is the entire fix.
    assert "MCP_SECRET_KEY" in str(exc.value.detail)


def test_embedded_without_a_key_still_works():
    """One process, so a process-local key verifies everything it signs."""
    keys = _plan_token_keys({"registry": {"mode": "embedded"}})
    assert len(keys) == 1


def test_a_configured_key_is_used_in_either_mode():
    from cryptography.fernet import Fernet

    cfg = {"registry": {"mode": "distributed"}, "gateway": {"secret_key": Fernet.generate_key().decode()}}
    assert _plan_token_keys(cfg)
    assert _plan_token_keys({**cfg, "registry": {"mode": "embedded"}})


def test_the_two_modes_do_not_share_the_ephemeral_key_by_accident():
    """Guards the shape rather than the value: if the distributed branch is ever removed, the
    fallback comes back silently and this is the test that notices."""
    embedded = _plan_token_keys({"registry": {"mode": "embedded"}})
    with pytest.raises(HTTPException):
        _plan_token_keys({"registry": {"mode": "distributed"}})
    assert embedded == _plan_token_keys({"registry": {"mode": "embedded"}})
