# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 §1 for OAuth2 — the half `ApiKeyAuth` has had since #131 and this handler had not.

§1a's table lists `client_secret` and `password` as by-reference alongside the API key, and
they were not: `OAuth2Auth` had no reference support at all and `client_secret` was mandatory
and inline. That is the concrete reason §3's simplification is blocked — an archive of an
OAuth2 fleet is still a credential dump, whatever else §3 says about archives.

**The design decision under test is that two secrets need two references.** A single
`credential_ref` was enough while an API key was the only case. `client_secret` and `password`
are provisioned and rotated independently by the tenant, so forcing them into one path with
two fragments would couple two secrets on different rotation schedules to one store location —
the opposite of what §1 buys. Hence `client_secret_ref` and `password_ref` on the wire, and
`credential_refs()` as the single accessor everything else reads, so a caller that wants "every
reference this device depends on" does not grow its own list of field names to look for.

**And `refresh_token` is deliberately not part of it** (§1a). The gateway is the only party
present when a provider rotates one, so there is nobody else to write it and a reference model
cannot describe it. `test_there_is_no_refresh_token_ref` is what keeps that from being "fixed".
"""

from __future__ import annotations

import json
import stat

import pytest

from device_mcp_gateway.auth.base import CredentialNotBound
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway.credentials.resolver import MountedFilesResolver, ReferenceInvalid

TENANT = "t-3f9a1c2b7d4e8065"
CLIENT_SECRET = "CLIENT-SECRET-c81b47f2"
PASSWORD = "PASSWORD-90ea3d16"
SECRET_REF = f"secret://{TENANT}/devices/erp#client-secret"
PASSWORD_REF = f"secret://{TENANT}/devices/erp#password"


@pytest.fixture()
def store(tmp_path):
    d = tmp_path / TENANT / "devices" / "erp"
    d.mkdir(parents=True)
    for name, value in (("client-secret", CLIENT_SECRET), ("password", PASSWORD)):
        f = d / name
        f.write_text(value)
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return MountedFilesResolver(str(tmp_path))


def _auth(**over):
    kwargs = dict(token_endpoint="https://idp.example.com/token", client_id="gateway")
    kwargs.update(over)
    return OAuth2Auth(**kwargs)


# ── Exactly one of each pair ─────────────────────────────────────────────────────────────


def test_a_client_secret_may_be_held_by_reference():
    auth = _auth(client_secret_ref=SECRET_REF)
    assert auth.client_secret is None
    assert auth.credential_refs() == {"client_secret_ref": SECRET_REF}


def test_inline_still_works_untouched():
    """The change permits a reference; it does not require one. Existing configs are configs
    that already work, and breaking them here would buy nothing — the refusal is a separate,
    gated decision."""
    auth = _auth(client_secret=CLIENT_SECRET)
    assert auth.credential_refs() == {}


def test_both_is_refused_rather_than_resolved_by_precedence():
    """Any precedence rule makes the losing value invisible, so a reference that silently never
    took effect looks exactly like one that did."""
    with pytest.raises(ValueError, match="mutually exclusive"):
        _auth(client_secret=CLIENT_SECRET, client_secret_ref=SECRET_REF)


def test_neither_is_refused_at_construction():
    with pytest.raises(ValueError, match="one of client_secret or client_secret_ref"):
        _auth()


def test_a_malformed_reference_fails_at_construction_not_at_dispatch():
    with pytest.raises(ReferenceInvalid):
        _auth(client_secret_ref="not-a-reference")


def test_password_by_reference_applies_only_to_the_password_grant():
    auth = _auth(client_secret=CLIENT_SECRET, grant_type="password", username="svc", password_ref=PASSWORD_REF)
    assert auth.credential_refs() == {"password_ref": PASSWORD_REF}


def test_a_password_ref_on_the_wrong_grant_is_refused():
    """A reference that is never resolved looks exactly like one that is — and the device would
    authenticate fine on client_credentials while its operator believed the password path was
    wired to the store."""
    with pytest.raises(ValueError, match="only meaningful for grant_type=password"):
        _auth(client_secret=CLIENT_SECRET, password_ref=PASSWORD_REF)


def test_client_credentials_does_not_demand_a_password():
    """The grant that carries no password must not be made to supply one of the pair."""
    assert _auth(client_secret=CLIENT_SECRET).password is None


# ── §1a's line: the gateway-minted token is not referenceable ────────────────────────────


def test_there_is_no_refresh_token_ref():
    """The boundary §1a draws, kept as a test so it is not "fixed" by symmetry.

    A refresh token is minted by the gateway mid-exchange — there is nobody else to write it,
    so a model that assumes an external writer cannot describe it. It stays encrypted at rest,
    and `MCP_SECRET_KEY` remains a named, permanent, bounded exception rather than a debt.
    """
    assert "refresh_token_ref" not in OAuth2Auth.__dataclass_fields__
    auth = _auth(client_secret_ref=SECRET_REF, grant_type="refresh_token", refresh_token="rt")
    assert "refresh_token" not in auth.credential_refs()
    assert "refresh_token" not in " ".join(auth.credential_refs())


# ── Resolution ───────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bind_resolves_both_references(store):
    auth = _auth(client_secret_ref=SECRET_REF, grant_type="password", username="svc", password_ref=PASSWORD_REF)
    await auth.bind(store)
    assert (auth.client_secret, auth.password) == (CLIENT_SECRET, PASSWORD)


@pytest.mark.asyncio
async def test_a_bound_handler_still_serialises_the_reference_not_the_secret(store):
    """The trap this shares with ApiKeyAuth: re-emitting a resolved value would write the
    secret back into the registry on the next update, quietly undoing ADR-0018 for the device
    while everything continued to look correct."""
    auth = _auth(client_secret_ref=SECRET_REF, grant_type="password", username="svc", password_ref=PASSWORD_REF)
    await auth.bind(store)

    blob = json.dumps(auth.to_dict())
    assert CLIENT_SECRET not in blob
    assert PASSWORD not in blob
    assert SECRET_REF in blob and PASSWORD_REF in blob


def test_a_round_trip_through_the_registry_shape_keeps_the_references():
    auth = _auth(client_secret_ref=SECRET_REF)
    assert OAuth2Auth.from_dict(auth.to_dict()).client_secret_ref == SECRET_REF


@pytest.mark.asyncio
async def test_a_token_fetch_without_a_resolver_fails_closed_and_says_which_thing_is_wrong():
    """Naming it apart from "the store said no" matters: the two send an operator to different
    systems, which is §7's reasoning one level down."""
    auth = _auth(client_secret_ref=SECRET_REF)
    with pytest.raises(CredentialNotBound, match="never given a credential resolver"):
        await auth.ensure_token()


@pytest.mark.asyncio
async def test_an_inline_handler_never_consults_a_resolver():
    """An all-inline fleet must not be made to depend on a secret store it never used."""

    class _Exploding:
        async def resolve(self, ref):
            raise AssertionError("resolver consulted for an inline credential")

    auth = _auth(client_secret=CLIENT_SECRET)
    auth.configure_credentials(_Exploding())
    await auth._ensure_bound()  # must be a no-op


# ── The restore-time check sees them, which is the point of one accessor ─────────────────


@pytest.mark.asyncio
async def test_the_restore_resolvability_check_finds_oauth2_references(tmp_path, store):
    """The reason `plan_credential_refs` reads `credential_refs()` rather than looking up a
    field name: an OAuth2 device holds its references under different keys, and a check with
    its own hardcoded list would report an unresolvable OAuth2 fleet as perfectly fine.
    """
    from cryptography.fernet import Fernet

    from device_mcp_gateway.backup.envelope import KIND_CIPHERTEXT, build_envelope, seal_canary
    from device_mcp_gateway.backup.restore import plan_credential_refs
    from device_mcp_gateway.shared.crypto import CredentialCodec

    codec = CredentialCodec.from_secret(Fernet.generate_key().decode())
    missing = f"secret://{TENANT}/devices/absent#client-secret"
    archive = build_envelope(
        kind=KIND_CIPHERTEXT, gateway_version="t", mode="embedded", canary=seal_canary(codec), counts={}
    )
    archive["devices"] = [
        {
            "hostname": "erp",
            "base_url": "https://erp.example.com",
            "auth_type": "oauth2",
            "auth_config": codec.encrypt(json.dumps(_auth(client_secret_ref=missing).to_dict())),
        }
    ]

    per_device, fleet = await plan_credential_refs(archive, codec, store)
    assert fleet is None
    assert "erp" in per_device, "an OAuth2 reference must be visible to the restore check"
    assert missing in per_device["erp"]
