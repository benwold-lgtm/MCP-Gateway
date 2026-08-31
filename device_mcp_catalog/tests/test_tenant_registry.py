# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §11 — the provider's tenant registry lives here, not in config.

§11's property, stated as the thing to test:

    Revoking an enrolment removes the tenant from the registry and the credential from the
    caller table, in one act, with no operator step in between — and a failure anywhere in the
    provider-side pair leaves neither behind.

The pairing is what these tests are about. Either half alone is a state the estate cannot
explain: a registry entry with no credential is a tenant the console lists and cannot serve, and
a credential with no registry entry is an orphan nothing would ever attribute.

**What is NOT tested here, because it cannot be:** the tenant gateway's own enrolment record is
a different system across a plane boundary and cannot join this transaction. §11 says so; the
provider console's compensation covers it, and `test_provider_enrolment.py` in the UI repo is
where that lives.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from device_mcp_catalog.app.auth import TENANT_HEADER
from device_mcp_catalog.app.main import create_app

PROVIDER_TOKEN = "provider-token"
TENANT_A = "t-aaaa"
TENANT_B = "t-bbbb"
GATEWAY_URL = "https://tenant-a.gateway.example"
GATEWAY_CREDENTIAL = "enr_provider_secret"

pytestmark = pytest.mark.integration


def _client(monkeypatch, database_url: str, *, secret_key: str = "") -> TestClient:
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    monkeypatch.delenv("CATALOG_TENANT_TOKENS", raising=False)
    monkeypatch.setenv("CATALOG_METRICS_ENABLED", "false")
    monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    if secret_key:
        monkeypatch.setenv("CATALOG_SECRET_KEY", secret_key)
    else:
        monkeypatch.delenv("CATALOG_SECRET_KEY", raising=False)
    return TestClient(create_app(), raise_server_exceptions=False)


def _provider() -> dict:
    return {"Authorization": f"Bearer {PROVIDER_TOKEN}"}


@pytest_asyncio.fixture
async def _clean(database_url):
    import asyncpg

    try:
        conn = await asyncpg.connect(database_url)
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")
    try:
        await conn.execute("TRUNCATE tenants, tenant_credentials")
    except asyncpg.UndefinedTableError:
        pass
    finally:
        await conn.close()


@pytest.fixture
def live(monkeypatch, database_url, _clean):
    client = _client(monkeypatch, database_url, secret_key=Fernet.generate_key().decode())
    with client:
        if client.get("/readyz").status_code != 200:
            pytest.skip("real Postgres not reachable")
        yield client


def _stored_credential(database_url: str, tenant_id: str = TENANT_A) -> str:
    """What the column actually holds. Read directly rather than through the service, because
    the claim under test is about storage — asking the app would only prove the codec is
    symmetric, which it would be either way."""
    import asyncio

    import asyncpg

    async def fetch():
        conn = await asyncpg.connect(database_url)
        try:
            return await conn.fetchval(
                "SELECT gateway_credential_encrypted FROM tenants WHERE tenant_id = $1", tenant_id
            )
        finally:
            await conn.close()

    return asyncio.get_event_loop().run_until_complete(fetch())


def _enrol(client, tenant_id=TENANT_A, **over):
    body = {
        "tenant_id": tenant_id,
        "display_name": "Acme",
        "gateway_url": GATEWAY_URL,
        "gateway_credential": GATEWAY_CREDENTIAL,
        "enrolment_id": "e-1",
    }
    body.update(over)
    return client.post("/tenants", headers=_provider(), json=body)


# --- the pair lands together ---------------------------------------------------------------


def test_enrolling_records_the_tenant_and_issues_its_credential_together(live):
    resp = _enrol(live)
    assert resp.status_code == 201, resp.text
    credential = resp.json()["credential"]

    listed = live.get("/tenants", headers=_provider()).json()["tenants"]
    assert [t["tenant_id"] for t in listed] == [TENANT_A]
    assert listed[0]["display_name"] == "Acme"

    # ...and the credential it issued in the same transaction actually authenticates.
    whoami = live.get("/whoami", headers={"Authorization": f"Bearer {credential}"})
    assert whoami.json() == {"kind": "tenant", "tenant_id": TENANT_A}


def test_neither_half_lands_when_the_pair_fails(live, database_url):
    """The reason it is one transaction. A tenant_id that violates the credential insert must
    leave no registry row behind — a registry entry with no credential is a tenant the console
    lists and cannot serve."""
    import asyncio

    import asyncpg

    from device_mcp_catalog.app.db import Database
    from device_mcp_catalog.app.repo import TenantRegistryRepo

    async def scenario():
        db = Database(database_url)
        await db.connect()
        try:
            repo = TenantRegistryRepo(db)
            common = dict(
                display_name="Acme",
                gateway_url=GATEWAY_URL,
                gateway_credential="x",
                enrolment_id="e-1",
                enrolled_by="provider",
                credential_label="l",
            )
            await repo.enrol(TENANT_A, credential_hash="dup-hash", **common)
            # `credential_hash` is UNIQUE, so a second enrolment reusing it fails inside the
            # transaction — after the registry upsert would otherwise have applied.
            with pytest.raises(asyncpg.UniqueViolationError):
                await repo.enrol(TENANT_B, credential_hash="dup-hash", **common)
            return await repo.list_tenants()
        finally:
            await db.close()

    tenants = asyncio.get_event_loop().run_until_complete(scenario())
    assert [t["tenant_id"] for t in tenants] == [TENANT_A], "the failed pair left a registry row behind"


# --- §11's property ------------------------------------------------------------------------


def test_withdrawing_removes_the_entry_and_revokes_the_credential_in_one_act(live):
    credential = _enrol(live).json()["credential"]
    assert live.get("/whoami", headers={"Authorization": f"Bearer {credential}"}).status_code == 200

    resp = live.delete(f"/tenants/{TENANT_A}", headers=_provider())
    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": TENANT_A, "removed": True, "credentials_revoked": 1}

    assert live.get("/tenants", headers=_provider()).json()["tenants"] == []
    assert live.get("/whoami", headers={"Authorization": f"Bearer {credential}"}).status_code == 401


def test_withdrawing_says_whether_there_was_anything_to_withdraw(live):
    """ "Ended a live relationship" and "there was nothing there" are different facts, and an
    operator ending a relationship during an incident needs to know which one happened."""
    resp = live.delete(f"/tenants/{TENANT_A}", headers=_provider())
    assert resp.json() == {"tenant_id": TENANT_A, "removed": False, "credentials_revoked": 0}


def test_withdrawing_one_tenant_does_not_touch_another(live):
    other = _enrol(live, tenant_id=TENANT_B).json()["credential"]
    _enrol(live)
    live.delete(f"/tenants/{TENANT_A}", headers=_provider())
    assert live.get("/whoami", headers={"Authorization": f"Bearer {other}"}).status_code == 200


def test_re_enrolling_replaces_the_entry_rather_than_failing(live):
    """The ordinary way to repair a relationship is to enrol again, so an upsert — not a
    conflict an operator has to resolve by withdrawing first."""
    _enrol(live)
    again = _enrol(live, display_name="Acme Renamed", gateway_url="https://moved.example")
    assert again.status_code == 201
    listed = live.get("/tenants", headers=_provider()).json()["tenants"]
    assert len(listed) == 1 and listed[0]["display_name"] == "Acme Renamed"


# --- the credential the provider has to present --------------------------------------------


def test_the_gateway_credential_round_trips_and_is_encrypted_at_rest(live, database_url):
    """The one stored value this service must PRESENT rather than merely recognise, so it is
    encrypted and not hashed — verified against what the table actually holds, not against the
    fact that a codec was configured."""
    _enrol(live)
    fetched = live.get(f"/tenants/{TENANT_A}/gateway-credential", headers=_provider())
    assert fetched.status_code == 200
    assert fetched.json()["gateway_credential"] == GATEWAY_CREDENTIAL
    assert fetched.json()["gateway_url"] == GATEWAY_URL

    stored = _stored_credential(database_url)
    assert stored != GATEWAY_CREDENTIAL and GATEWAY_CREDENTIAL not in stored


def test_an_unenrolled_tenant_is_a_named_condition(live):
    assert live.get(f"/tenants/{TENANT_B}/gateway-credential", headers=_provider()).status_code == 404


def test_the_listing_carries_no_credentials(live):
    _enrol(live)
    listed = live.get("/tenants", headers=_provider()).json()["tenants"][0]
    assert GATEWAY_CREDENTIAL not in str(listed)
    assert not any("credential" in key for key in listed)


# --- authority -----------------------------------------------------------------------------


def test_the_registry_is_provider_only(live):
    """A tenant reading the estate would learn who else the provider serves — the commercial
    intelligence ADR-0020 §7a already refuses to hand out."""
    credential = _enrol(live).json()["credential"]
    tenant = {"Authorization": f"Bearer {credential}", TENANT_HEADER: TENANT_A}
    assert live.get("/tenants", headers=tenant).status_code == 403
    assert live.post("/tenants", headers=tenant, json={}).status_code == 403
    assert live.delete(f"/tenants/{TENANT_A}", headers=tenant).status_code == 403
    assert live.get(f"/tenants/{TENANT_A}/gateway-credential", headers=tenant).status_code == 403


# --- the ordering the handshake forces ------------------------------------------------------


def test_the_gateway_credential_can_be_filled_in_after_enrolment(live, database_url):
    """The enrolment ordering leaves no choice: the tenant's catalog credential must exist
    before the redemption, because the redemption is what hands it over, and the provider's own
    credential only exists after it. So the row is created empty and completed here."""
    _enrol(live, gateway_credential="")
    assert live.get(f"/tenants/{TENANT_A}/gateway-credential", headers=_provider()).json()["gateway_credential"] == ""

    resp = live.put(
        f"/tenants/{TENANT_A}/gateway-credential",
        headers=_provider(),
        json={"gateway_credential": GATEWAY_CREDENTIAL, "enrolment_id": "e-9"},
    )
    assert resp.status_code == 200

    fetched = live.get(f"/tenants/{TENANT_A}/gateway-credential", headers=_provider()).json()
    assert fetched["gateway_credential"] == GATEWAY_CREDENTIAL
    assert live.get("/tenants", headers=_provider()).json()["tenants"][0]["enrolment_id"] == "e-9"

    # Encrypted here too. Asserted separately from the enrol path above because they are two
    # different writes, and a codec applied on one and forgotten on the other would round-trip
    # perfectly while storing the credential in the clear.
    assert GATEWAY_CREDENTIAL not in _stored_credential(database_url)


def test_completing_an_enrolment_does_not_mint_a_second_credential(live):
    """Why this is a PUT of its own and not `POST /tenants` again. Re-posting would upsert the
    registry row and mint another catalog credential for a tenant that already holds a live one
    — which is exactly how a caller table acquires entries nobody can account for."""
    _enrol(live, gateway_credential="")
    live.put(
        f"/tenants/{TENANT_A}/gateway-credential",
        headers=_provider(),
        json={"gateway_credential": GATEWAY_CREDENTIAL},
    )
    listed = live.get(f"/tenants/{TENANT_A}/credentials", headers=_provider()).json()["credentials"]
    assert len(listed) == 1, "completing an enrolment must not issue another credential"


def test_recording_against_an_unenrolled_tenant_is_refused_not_silently_dropped(live):
    """A write that lands nowhere and reports success is the shape of defect this repo has
    corrected before — an UPDATE matching no rows is not an outcome a caller can act on."""
    resp = live.put(
        f"/tenants/{TENANT_B}/gateway-credential",
        headers=_provider(),
        json={"gateway_credential": GATEWAY_CREDENTIAL},
    )
    assert resp.status_code == 404


def test_an_empty_gateway_credential_is_refused(live):
    """Blanking the column would leave a tenant listed and unreachable while reading as a
    successful write. Withdrawing is how a relationship ends; this route only completes one."""
    _enrol(live)
    resp = live.put(f"/tenants/{TENANT_A}/gateway-credential", headers=_provider(), json={"gateway_credential": ""})
    assert resp.status_code == 400
    assert live.get(f"/tenants/{TENANT_A}/gateway-credential", headers=_provider()).json()["gateway_credential"]


def test_completing_an_enrolment_is_provider_only(live):
    credential = _enrol(live).json()["credential"]
    tenant = {"Authorization": f"Bearer {credential}", TENANT_HEADER: TENANT_A}
    resp = live.put(f"/tenants/{TENANT_A}/gateway-credential", headers=tenant, json={"gateway_credential": "x"})
    assert resp.status_code == 403
