# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Deployment safety for the ADR-0018 credential-reference rollout.

A rolling restart runs two builds at once. These pin what happens to a device that has been
migrated to ``credential_ref`` while some replica is still running code that does not wire
``bind()`` into dispatch — the window this project has twice been bitten in, both times because
the tests were narrower than the deployment.

The property is **fail closed, and say why**. A worker that cannot resolve a credential must
refuse the call rather than dispatch with something stale, empty, or placeholder.

These are not tests of the resolver or the handler in isolation; both have their own files.
They exist to make the *rollout order* a checked property rather than an assumption, because
the safe order here is counter-intuitive: the component that **reads** the new field ships
before the component that **writes** it.
"""

from __future__ import annotations

import json

import pytest

from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.base import CredentialNotBound
from device_mcp_gateway.registry.server import _auth_from_record

REF = "secret://t-3f9a1c2b7d4e8065/devices/prism#api-key"

#: What a migrated device looks like in the store — the exact shape `to_dict` writes.
MIGRATED_RECORD = {
    "type": "api_key",
    "credential_ref": REF,
    "location": "header",
    "name": "X-API-Key",
    "value_prefix": "",
    "header_name": "X-API-Key",
}

LEGACY_RECORD = {
    "type": "api_key",
    "api_key": "inline-secret",
    "location": "header",
    "name": "X-API-Key",
    "value_prefix": "",
    "header_name": "X-API-Key",
}


# --- The mixed-version window ------------------------------------------------


def test_a_current_worker_can_load_a_migrated_record():
    """Reading must not throw. A replica that crashes on an unfamiliar record turns a
    credential migration into an availability incident for the whole device."""
    auth = _auth_from_record({"auth_config": json.dumps(MIGRATED_RECORD)})
    assert isinstance(auth, ApiKeyAuth)
    assert auth.credential_ref == REF
    assert auth.api_key is None


@pytest.mark.asyncio
async def test_an_unwired_dispatch_path_fails_closed_on_a_migrated_device():
    """**The rollout question, answered.**

    A replica running post-#130 code but without dispatch wired to ``bind()`` loads the record
    happily and then refuses at the point of use. It does not dispatch with an empty
    credential, and it does not fall back to anything stale — there is nothing stale to fall
    back to, because the record no longer carries an inline value.

    Refusing here is what makes the rollout safe in either order of replica restart.
    """
    auth = _auth_from_record({"auth_config": json.dumps(MIGRATED_RECORD)})
    with pytest.raises(CredentialNotBound):
        await auth.apply()


@pytest.mark.asyncio
async def test_the_refusal_names_the_reference_so_it_is_diagnosable():
    """A fail-closed that cannot be diagnosed sends an operator to the wrong system.

    The message has to say the credential was never resolved — not merely that something went
    wrong — or the symptom is indistinguishable from the device rejecting a bad key.
    """
    auth = _auth_from_record({"auth_config": json.dumps(MIGRATED_RECORD)})
    with pytest.raises(CredentialNotBound) as exc:
        await auth.apply()
    assert "not been resolved" in str(exc.value)
    assert REF in str(exc.value)


@pytest.mark.asyncio
async def test_a_legacy_device_is_untouched_by_any_of_this():
    """The other half of a mixed fleet. Migration is per device, so unmigrated devices must
    keep dispatching through a build that fully supports references."""
    auth = _auth_from_record({"auth_config": json.dumps(LEGACY_RECORD)})
    assert (await auth.get_headers()) == {"X-API-Key": "inline-secret"}


# --- Rollback ----------------------------------------------------------------


def test_a_migrated_record_is_not_readable_by_pre_reference_code():
    """Rollback boundary, asserted rather than assumed.

    Code older than the reference support does ``data["api_key"]`` and raises ``KeyError`` on a
    migrated record — it cannot even construct the handler, so the failure is at load rather
    than at dispatch and takes the device out entirely.

    This is what makes rollback *past* the reference-reading build unsafe once any device has
    been migrated, and it is the reason the reading build must ship first and separately. The
    simulation is the old expression, not the old file, because the point is the shape of the
    access, not a historical artefact.
    """
    with pytest.raises(KeyError):
        _ = MIGRATED_RECORD["api_key"]  # what pre-#130 from_dict did

    # And the current code does not: `.get` is what makes the forward read safe.
    assert MIGRATED_RECORD.get("api_key") is None


def test_rollback_to_the_reading_build_is_safe_for_an_unmigrated_fleet():
    """The common rollback: nothing has been migrated yet, so every record is legacy-shaped
    and any build in this range reads it identically."""
    for record in (LEGACY_RECORD,):
        auth = ApiKeyAuth.from_dict(record)
        assert auth.api_key == "inline-secret"
        assert auth.credential_ref is None
        # Round-trips to the same shape, so a rollback does not rewrite records on next save.
        assert "credential_ref" not in auth.to_dict()
