# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §10 — the tenant invites, the provider redeems, and the relationship is revocable.

§10's own property, stated as the thing to test:

    Every piece of state the connection depends on is created by approving the enrolment, and
    removed by revoking it. No step in the nine may remain something a human does separately
    and correctly.

The half of that this slice can prove is the gateway's: redemption mints the provider's
standing credential and records the tenant's catalog details in one act, and revoking refuses
the very next request. The other half — that the provider's registry and the catalog's own
credential are created by the same act — belongs to the slices that build those sides.

Run against the real `create_app()` wiring rather than the stores directly, because the thing
worth proving is that a credential nobody typed into config gets a caller through
`authenticate_request` and onto a route, with exactly one verb.
"""

from __future__ import annotations

import itertools
import time

import pytest
from fastapi.testclient import TestClient

_STACK_SEQ = itertools.count()
ADMIN_KEY = "a" * 40
CATALOG_URL = "https://catalog.provider.example"
CATALOG_CREDENTIAL = "tenant-catalog-token"
TENANT_ID = "t-3f9a1c2b7d4e8065"


def _client(monkeypatch, tmp_path, *, tenant_id: str | None = TENANT_ID) -> TestClient:
    stack_dir = tmp_path / f"stack-{next(_STACK_SEQ)}"
    stack_dir.mkdir()
    # A stack that cannot say which tenant it is cannot be enrolled, so every client here
    # configures one — `tenant_id=None` is how the refusal itself is tested.
    #
    # ⚠️ The config is loaded EXPLICITLY and passed in, not selected via `MCP_CONFIG`. That env
    # var is read into `cfg.CONFIG_PATH` at module-import time and then baked into
    # `load_config`'s default argument, so the FIRST test in a session to import the gateway
    # fixes the config path for every test after it — setting it per-test looks like it works
    # and silently does nothing. (Found here: whichever of these tests ran first decided
    # whether the rest saw a tenant id.) Passing `override_config` is the only per-test route
    # that is not at the mercy of import order.
    config_path = stack_dir / "config.yaml"
    config_path.write_text(f'gateway:\n  tenant_id: "{tenant_id}"\n' if tenant_id else "gateway: {}\n")
    monkeypatch.chdir(stack_dir)
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    from device_mcp_gateway.cfg import load_config
    from device_mcp_gateway.main import create_app

    return TestClient(create_app(override_config=load_config(str(config_path))))


def _admin() -> dict:
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def _invite(client, *, label: str = "Acme Support", ttl: int = 3600) -> str:
    resp = client.post(
        "/v1/enrolment-invitations", headers=_admin(), json={"provider_label": label, "ttl_seconds": ttl}
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["code"]


def _redeem(client, code: str, *, subject: str = "oidc:provider-idp#op1", **overrides):
    body = {
        "provider_subject": subject,
        "catalog_url": CATALOG_URL,
        "catalog_credential": CATALOG_CREDENTIAL,
    }
    body.update(overrides)
    return client.post("/v1/enrolments/redeem", headers={"Authorization": f"Bearer {code}"}, json=body)


def _enrol(client, **kwargs) -> str:
    """The whole handshake, as a real pair would perform it. Never construct a credential."""
    resp = _redeem(client, _invite(client), **kwargs)
    assert resp.status_code == 201, resp.text
    return resp.json()["credential"]


# --- the invitation is the bootstrap, and only that ----------------------------------------


def test_creating_an_invitation_needs_the_administer_scope(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/enrolment-invitations", json={"provider_label": "Acme"})
    assert resp.status_code == 401


def test_an_invitation_names_who_it_is_for(monkeypatch, tmp_path):
    """Refused rather than defaulted: an invitation nobody can attribute is one nobody can
    safely hand over, and the label is what the tenant's listing shows later."""
    client = _client(monkeypatch, tmp_path)
    resp = client.post("/v1/enrolment-invitations", headers=_admin(), json={})
    assert resp.status_code == 400


def test_an_invitation_code_cannot_authenticate_an_ordinary_request(monkeypatch, tmp_path):
    """The prefix separation, and the reason it exists. If a bootstrap secret handed over in an
    email could authenticate ordinary requests, the handover would be standing access to the
    tenant's gateway."""
    client = _client(monkeypatch, tmp_path)
    code = _invite(client)

    assert client.get("/v1/devices", headers={"Authorization": f"Bearer {code}"}).status_code == 401
    assert client.get("/v1/enrolments", headers={"Authorization": f"Bearer {code}"}).status_code == 401


def test_an_enrolment_credential_cannot_redeem(monkeypatch, tmp_path):
    """The separation in the other direction: a standing credential is not a one-time one.

    Note what actually refuses it — redemption resolves against the INVITATION store, and an
    enrolment credential was never written there. The `inv_` prefix check in the route is a
    cheap shape guard on top of that, not the boundary: removing it leaves this test passing.
    Worth stating, because a test that would pass for an incidental reason is one that stops
    meaning what its name says.
    """
    client = _client(monkeypatch, tmp_path)
    credential = _enrol(client)
    assert _redeem(client, credential).status_code == 401


# --- redemption is single-use and atomic ---------------------------------------------------


def test_a_stack_that_cannot_name_its_tenant_refuses_to_be_enrolled(monkeypatch, tmp_path):
    """§10 praises step 5 of its nine for failing "loudly, at startup, naming the missing
    field" — the model failure mode. This is that shape at the first moment it can matter.

    The provider uses the returned `tenant_id` to check the catalog credential it minted was
    minted for the tenant it actually reached. Answering `null` would make that check optional,
    and an optional check is skipped by exactly the deployment that got it wrong.
    """
    client = _client(monkeypatch, tmp_path, tenant_id=None)
    resp = _redeem(client, _invite(client))
    assert resp.status_code == 409
    assert resp.json()["detail"]["error_code"] == "ERR_TENANT_ID_NOT_CONFIGURED"


def test_redemption_tells_the_provider_which_tenant_it_enrolled(monkeypatch, tmp_path):
    """From this stack's OWN configuration, never from anything the redeeming caller sent —
    the rule `provider_subject` and `assigned_by` already follow."""
    client = _client(monkeypatch, tmp_path)
    assert _redeem(client, _invite(client)).json()["tenant_id"] == TENANT_ID


def test_redemption_mints_a_credential_and_records_who_approved_it(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    resp = _redeem(client, _invite(client))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["credential"].startswith("enr_")
    # §10's replacement for expiry starts here: the listing must be able to say who approved
    # this and when, and `approved_by` is the TENANT ADMIN who issued the invitation — not the
    # provider redeeming it, who supplies nothing about the tenant's side of the relationship
    # and must not be able to write its own approver.
    assert body["approved_by"] == "key:admin"
    assert body["approved_at"] > 0


def test_an_invitation_redeems_exactly_once(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    code = _invite(client)
    assert _redeem(client, code).status_code == 201
    assert _redeem(client, code).status_code == 401


def test_an_expired_invitation_is_refused(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    code = _invite(client, ttl=-1)
    assert _redeem(client, code).status_code == 401


def test_an_unknown_code_is_refused_the_same_way_as_a_malformed_one(monkeypatch, tmp_path):
    """Deliberately indistinguishable. An endpoint outside authentication that told the two
    apart would let an uninvited caller probe for the shape of a valid code."""
    client = _client(monkeypatch, tmp_path)
    unknown = _redeem(client, "inv_" + "z" * 40)
    malformed = _redeem(client, "not-even-close")
    assert unknown.status_code == malformed.status_code == 401
    assert unknown.json()["detail"] == malformed.json()["detail"]


@pytest.mark.parametrize("missing", ["catalog_url", "catalog_credential", "provider_subject"])
def test_redemption_refuses_an_incomplete_handshake(monkeypatch, tmp_path, missing):
    """Step 9 of §10's nine fails quietly and reads as "the catalog is down" while it is
    healthy. A redemption that succeeded without the catalog's details would produce an
    enrolment that looks complete and leaves the tenant's catalog silently unreachable."""
    client = _client(monkeypatch, tmp_path)
    resp = _redeem(client, _invite(client), **{missing: ""})
    assert resp.status_code == 400
    assert missing in resp.json()["detail"]


# --- what the enrolment credential can and cannot do ---------------------------------------


def test_the_credential_authenticates_and_carries_exactly_one_verb(monkeypatch, tmp_path):
    """§10 can only justify giving an enrolment no expiry because its side permits one verb —
    *ask*. That is a claim about scopes, so it is tested as one."""
    client = _client(monkeypatch, tmp_path)
    credential = _enrol(client)
    auth = {"Authorization": f"Bearer {credential}"}

    raised = client.post(
        "/v1/support-requests",
        headers=auth,
        json={"provider_subject": "oidc:provider-idp#op1", "requested_scopes": ["devices:read"], "justification": "x"},
    )
    assert raised.status_code == 201, raised.text

    # Reads no device, decides nothing, administers nothing.
    assert client.get("/v1/devices", headers=auth).status_code == 403
    assert client.get("/v1/support-requests", headers=auth).status_code == 403
    assert client.get("/v1/enrolments", headers=auth).status_code == 403


def test_the_provider_cannot_enrol_itself(monkeypatch, tmp_path):
    """§10: "a provider that could enrol itself would be choosing its own customers." An
    enrolled provider holds no authority to mint another invitation."""
    client = _client(monkeypatch, tmp_path)
    credential = _enrol(client)
    resp = client.post(
        "/v1/enrolment-invitations",
        headers={"Authorization": f"Bearer {credential}"},
        json={"provider_label": "Acme"},
    )
    assert resp.status_code == 403


# --- revocation is the only control, so it has to be immediate -----------------------------


def test_revoking_refuses_the_very_next_request(monkeypatch, tmp_path):
    """The property that lets §10 justify no expiry. Checked live on every request, not cached
    — with no expiry, revocation is the ONLY control there is."""
    client = _client(monkeypatch, tmp_path)
    credential = _enrol(client)
    auth = {"Authorization": f"Bearer {credential}"}
    raise_body = {
        "provider_subject": "oidc:provider-idp#op1",
        "requested_scopes": ["devices:read"],
        "justification": "x",
    }
    assert client.post("/v1/support-requests", headers=auth, json=raise_body).status_code == 201

    enrolment_id = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]["enrolment_id"]
    assert client.delete(f"/v1/enrolments/{enrolment_id}", headers=_admin()).status_code == 204

    assert client.post("/v1/support-requests", headers=auth, json=raise_body).status_code == 401


def test_revoking_is_idempotent(monkeypatch, tmp_path):
    """ADR-0017 §8's reasoning: a tenant ending a supplier relationship is very often doing so
    because something is wrong right now, and a button that errors on the second click is one
    that fails when it matters."""
    client = _client(monkeypatch, tmp_path)
    _enrol(client)
    enrolment_id = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]["enrolment_id"]
    assert client.delete(f"/v1/enrolments/{enrolment_id}", headers=_admin()).status_code == 204
    assert client.delete(f"/v1/enrolments/{enrolment_id}", headers=_admin()).status_code == 204


def test_a_revoked_enrolment_leaves_the_listing(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _enrol(client)
    enrolment_id = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]["enrolment_id"]
    client.delete(f"/v1/enrolments/{enrolment_id}", headers=_admin())
    assert client.get("/v1/enrolments", headers=_admin()).json()["enrolments"] == []


# --- what replaces expiry: the listing, and last-used ---------------------------------------


def test_the_listing_carries_who_approved_it_and_the_catalog_it_points_at(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _enrol(client)
    row = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]
    assert row["provider_label"] == "Acme Support"
    assert row["provider_subject"] == "oidc:provider-idp#op1"
    assert row["catalog_url"] == CATALOG_URL
    assert row["approved_by"]
    assert row["approved_at"] > 0


def test_last_used_is_absent_until_the_provider_actually_uses_it(monkeypatch, tmp_path):
    """`None` is the dormancy signal the listing exists for — "approved and never used" is a
    different fact from "used at some point", and a self-reported or approval-time default
    would erase the distinction §10 asks the console to surface."""
    client = _client(monkeypatch, tmp_path)
    credential = _enrol(client)

    assert client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]["last_used_at"] is None

    before = time.time()
    client.post(
        "/v1/support-requests",
        headers={"Authorization": f"Bearer {credential}"},
        json={"provider_subject": "oidc:provider-idp#op1", "requested_scopes": ["devices:read"], "justification": "x"},
    )
    last_used = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]["last_used_at"]
    assert last_used is not None and last_used >= before


def test_an_outstanding_invitation_is_listed_and_can_be_withdrawn(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _invite(client, label="Acme Support")
    listed = client.get("/v1/enrolment-invitations", headers=_admin()).json()["invitations"]
    assert len(listed) == 1 and listed[0]["provider_label"] == "Acme Support"
    # The listing shows the hash, never the code — the plaintext existed once, in the response
    # that created it.
    assert "code" not in listed[0]

    assert client.delete(f"/v1/enrolment-invitations/{listed[0]['code_hash']}", headers=_admin()).status_code == 204
    assert client.get("/v1/enrolment-invitations", headers=_admin()).json()["invitations"] == []


def test_a_withdrawn_invitation_cannot_be_redeemed(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    code = _invite(client)
    code_hash = client.get("/v1/enrolment-invitations", headers=_admin()).json()["invitations"][0]["code_hash"]
    client.delete(f"/v1/enrolment-invitations/{code_hash}", headers=_admin())
    assert _redeem(client, code).status_code == 401


# --- the credential the tenant actually has to use -----------------------------------------


def test_the_tenant_can_read_back_the_catalog_credential_it_was_given(monkeypatch, tmp_path):
    """§10: "the tenant receives the catalog's address and its own credential for it."

    This is the one credential in the enrolment that must be READABLE rather than merely
    recognisable — the tenant's console presents it to the catalog on every request. An
    enrolment that stored it one-way would look complete and leave the catalog silently
    unreachable, which is step 9 of §10's nine and the exact failure this mechanism removes.
    """
    client = _client(monkeypatch, tmp_path)
    _enrol(client)

    resp = client.get("/v1/enrolments/catalog-configuration", headers=_admin())
    assert resp.status_code == 200, resp.text
    assert resp.json()["catalog_url"] == CATALOG_URL
    assert resp.json()["catalog_credential"] == CATALOG_CREDENTIAL


def test_no_enrolment_is_a_named_condition_not_an_empty_configuration(monkeypatch, tmp_path):
    """ "Not enrolled" and "enrolled with nothing configured" are different, and a console that
    could not tell them apart would show an empty catalog for both — the named-condition
    discipline ADR-0020 §7 already requires of the catalog itself."""
    client = _client(monkeypatch, tmp_path)
    assert client.get("/v1/enrolments/catalog-configuration", headers=_admin()).status_code == 404


def test_revoking_closes_the_tenants_catalog_access(monkeypatch, tmp_path):
    """The other half of §10's property: revoking removes every piece of state the connection
    depends on, on both sides. The provider loses the ability to raise (above), and the
    tenant's catalog closes."""
    client = _client(monkeypatch, tmp_path)
    _enrol(client)
    enrolment_id = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]["enrolment_id"]
    client.delete(f"/v1/enrolments/{enrolment_id}", headers=_admin())

    assert client.get("/v1/enrolments/catalog-configuration", headers=_admin()).status_code == 404


def test_the_catalog_credential_is_not_in_the_listing(monkeypatch, tmp_path):
    """A listing is a screen an admin leaves open. The credential is fetched by the component
    that needs it, when it needs it, and never rendered beside "who approved this and when"."""
    client = _client(monkeypatch, tmp_path)
    _enrol(client)
    row = client.get("/v1/enrolments", headers=_admin()).json()["enrolments"][0]
    assert CATALOG_CREDENTIAL not in str(row)
    assert not any("credential" in key for key in row)


def test_the_provider_cannot_read_the_tenants_catalog_credential(monkeypatch, tmp_path):
    """It is the tenant's credential, minted for the tenant. The provider supplied it once at
    redemption and holds one verb thereafter."""
    client = _client(monkeypatch, tmp_path)
    credential = _enrol(client)
    resp = client.get("/v1/enrolments/catalog-configuration", headers={"Authorization": f"Bearer {credential}"})
    assert resp.status_code == 403


def test_the_catalog_credential_is_encrypted_at_rest_when_a_key_is_configured(monkeypatch, tmp_path):
    """Encrypted under the gateway's existing CredentialCodec, not a second scheme — and
    verified by looking at what the store actually holds rather than trusting that a codec was
    passed. With no MCP_SECRET_KEY the codec is a documented no-op, so the key is set here to
    test the configuration that has one."""
    from cryptography.fernet import Fernet

    monkeypatch.setenv("MCP_SECRET_KEY", Fernet.generate_key().decode())
    client = _client(monkeypatch, tmp_path)
    _enrol(client)

    stored = client.app.state.enrolments._enrolments
    at_rest = next(iter(stored.values())).catalog_credential_encrypted
    assert at_rest != CATALOG_CREDENTIAL
    assert CATALOG_CREDENTIAL not in at_rest
    # ...and still round-trips through the route the tenant console uses.
    assert (
        client.get("/v1/enrolments/catalog-configuration", headers=_admin()).json()["catalog_credential"]
        == CATALOG_CREDENTIAL
    )
