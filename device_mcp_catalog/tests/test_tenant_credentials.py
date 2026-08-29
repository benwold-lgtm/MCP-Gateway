# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §10 — the tenant caller table stops being static config.

ADR-0020 §7a made the catalog authenticate two caller classes but had nothing that could
*mint* a tenant's credential, so the table lived in `CATALOG_TENANT_TOKENS`. §10 supplies the
lifecycle: approving an enrolment is when a credential should be issued, and revoking one is
when it should end.

Most of this needs a real store, so it is integration-marked. The exception is deliberate and
at the bottom: **an unreachable database must refuse as a named 503, not as a 401**, and that
is provable with no database precisely because there is no database.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from device_mcp_catalog.app.auth import TENANT_HEADER
from device_mcp_catalog.app.main import create_app

PROVIDER_TOKEN = "provider-token"
TENANT_A = "t-aaaa"
TENANT_B = "t-bbbb"


def _client(monkeypatch, database_url: str = "", *, tenant_tokens: str = "") -> TestClient:
    monkeypatch.setenv("CATALOG_API_TOKEN", PROVIDER_TOKEN)
    # Set explicitly rather than left to the ambient environment: this helper used to always
    # clear it, which silently unset what a caller had just configured.
    if tenant_tokens:
        monkeypatch.setenv("CATALOG_TENANT_TOKENS", tenant_tokens)
    else:
        monkeypatch.delenv("CATALOG_TENANT_TOKENS", raising=False)
    monkeypatch.setenv("CATALOG_METRICS_ENABLED", "false")
    if database_url:
        monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    else:
        monkeypatch.delenv("CATALOG_DATABASE_URL", raising=False)
    return TestClient(create_app(), raise_server_exceptions=False)


def _provider() -> dict:
    return {"Authorization": f"Bearer {PROVIDER_TOKEN}"}


def _as_tenant(credential: str, tenant_id: str) -> dict:
    return {"Authorization": f"Bearer {credential}", TENANT_HEADER: tenant_id}


# --- the one case that needs no database ---------------------------------------------------


def test_an_unreachable_store_is_a_named_503_not_an_invalid_credential(monkeypatch):
    """The distinction matters more than it looks. A 401 tells an operator their credential is
    wrong, so a database outage would be diagnosed as a misconfiguration — sending someone to
    re-issue a credential that was fine. ADR-0020 §7 already requires this service's
    unavailability to be a named condition; this is that rule reaching the one path where the
    wrong answer actively misleads rather than merely unhelps.

    Proven with a database that is configured but unreachable, which is the shape a real outage
    takes: a *missing* one is a different condition (nothing to look up, and `/readyz` is where
    that is reported) and correctly stays a 401.
    """
    client = _client(monkeypatch, "postgresql://nobody:nobody@127.0.0.1:1/does-not-exist")
    with client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_as_tenant("cat_whatever", TENANT_A))
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["error_code"] == "ERR_CATALOG_STORE_UNAVAILABLE"


def test_no_database_configured_still_refuses_an_unknown_credential(monkeypatch):
    """The other half: with no store at all there is nothing to look up and nothing to claim is
    broken about the credential. Refusing as 401 is right; a 503 here would report an outage
    the operator does not have."""
    client = _client(monkeypatch)
    with client:
        resp = client.get(f"/tenants/{TENANT_A}/assignments", headers=_as_tenant("cat_whatever", TENANT_A))
    assert resp.status_code == 401


# --- everything else needs the real store --------------------------------------------------

pytestmark_integration = pytest.mark.integration


@pytest_asyncio.fixture
async def _clean(database_url):
    import asyncpg

    try:
        conn = await asyncpg.connect(database_url)
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")
    try:
        await conn.execute("TRUNCATE tenant_credentials")
    except asyncpg.UndefinedTableError:
        pass
    finally:
        await conn.close()


@pytest.fixture
def live(monkeypatch, database_url, _clean):
    client = _client(monkeypatch, database_url)
    with client:
        if client.get("/readyz").status_code != 200:
            pytest.skip("real Postgres not reachable")
        yield client


def _issue(client, tenant_id: str, label: str = "enrolment") -> tuple[str, str]:
    resp = client.post(f"/tenants/{tenant_id}/credentials", headers=_provider(), json={"label": label})
    assert resp.status_code == 201, resp.text
    return resp.json()["credential"], resp.json()["id"]


@pytestmark_integration
def test_an_issued_credential_authenticates_as_its_tenant(live):
    """The whole point: a credential nobody typed into config resolves to the right caller."""
    credential, _ = _issue(live, TENANT_A)
    assert credential.startswith("cat_")

    whoami = live.get("/whoami", headers={"Authorization": f"Bearer {credential}"})
    assert whoami.status_code == 200
    assert whoami.json() == {"kind": "tenant", "tenant_id": TENANT_A}


@pytestmark_integration
def test_an_issued_credential_is_scoped_like_a_configured_one(live):
    """§7a's rules do not care where the credential came from. An issued one is refused for
    naming another tenant exactly as a configured one is — the two sources produce the same
    caller class, which is what makes adding a source safe."""
    credential, _ = _issue(live, TENANT_A)
    assert live.get(f"/tenants/{TENANT_B}/assignments", headers=_as_tenant(credential, TENANT_A)).status_code == 403
    assert live.get("/device-types", headers=_as_tenant(credential, TENANT_A)).status_code == 403


@pytestmark_integration
def test_an_issued_credential_still_has_to_declare_itself(live):
    """And §7b's rule likewise. A credential minted by an enrolment gets no exemption from the
    declaration — an issued credential misdelivered is exactly as invisible as a configured
    one, and arguably likelier, since issuing is automated and copying is not."""
    credential, _ = _issue(live, TENANT_A)
    undeclared = live.get(f"/tenants/{TENANT_A}/assignments", headers={"Authorization": f"Bearer {credential}"})
    assert undeclared.status_code == 403
    assert undeclared.json()["detail"]["error_code"] == "ERR_TENANT_NOT_DECLARED"

    misdelivered = live.get(f"/tenants/{TENANT_B}/assignments", headers=_as_tenant(credential, TENANT_B))
    assert misdelivered.json()["detail"]["error_code"] == "ERR_CREDENTIAL_MISDELIVERY"


@pytestmark_integration
def test_revoking_refuses_the_very_next_request(live):
    """Revocation is the only control an issued credential has, so it is resolved live on every
    request rather than from anything cached."""
    credential, credential_id = _issue(live, TENANT_A)
    assert live.get("/whoami", headers={"Authorization": f"Bearer {credential}"}).status_code == 200

    assert live.delete(f"/tenants/{TENANT_A}/credentials/{credential_id}", headers=_provider()).status_code == 204
    assert live.get("/whoami", headers={"Authorization": f"Bearer {credential}"}).status_code == 401


@pytestmark_integration
def test_revoking_every_credential_at_once_is_what_ending_an_enrolment_calls(live):
    """§10: "revoking an enrolment revokes that credential too." One call rather than a client
    loop, so ending a relationship cannot half-happen because something interrupted the caller
    between two revokes."""
    first, _ = _issue(live, TENANT_A, "one")
    second, _ = _issue(live, TENANT_A, "two")
    other, _ = _issue(live, TENANT_B, "elsewhere")

    resp = live.delete(f"/tenants/{TENANT_A}/credentials", headers=_provider())
    assert resp.status_code == 200 and resp.json()["revoked"] == 2

    assert live.get("/whoami", headers={"Authorization": f"Bearer {first}"}).status_code == 401
    assert live.get("/whoami", headers={"Authorization": f"Bearer {second}"}).status_code == 401
    # And nobody else's. A bulk revoke that reached another tenant would be the cross-tenant
    # blast radius this estate is shaped to avoid, in the one operation built to be sweeping.
    assert live.get("/whoami", headers={"Authorization": f"Bearer {other}"}).status_code == 200


@pytestmark_integration
def test_revoking_is_idempotent(live):
    _, credential_id = _issue(live, TENANT_A)
    assert live.delete(f"/tenants/{TENANT_A}/credentials/{credential_id}", headers=_provider()).status_code == 204
    assert live.delete(f"/tenants/{TENANT_A}/credentials/{credential_id}", headers=_provider()).status_code == 204


@pytestmark_integration
def test_a_credential_is_returned_once_and_never_again(live):
    """No route re-shows it, and the listing carries neither the secret nor its hash — a hash
    in a listing is something to compare a candidate token against."""
    credential, _ = _issue(live, TENANT_A)
    listed = live.get(f"/tenants/{TENANT_A}/credentials", headers=_provider()).json()["credentials"]
    assert len(listed) == 1
    assert credential not in str(listed)
    assert not any("hash" in key or "credential" == key for key in listed[0])


@pytestmark_integration
def test_issuing_and_revoking_are_provider_only(live):
    """A tenant console minting its own credential would be the authorization model asking the
    applicant to fill in their own pass."""
    credential, credential_id = _issue(live, TENANT_A)
    tenant = _as_tenant(credential, TENANT_A)
    assert live.post(f"/tenants/{TENANT_A}/credentials", headers=tenant, json={}).status_code == 403
    assert live.get(f"/tenants/{TENANT_A}/credentials", headers=tenant).status_code == 403
    assert live.delete(f"/tenants/{TENANT_A}/credentials/{credential_id}", headers=tenant).status_code == 403


@pytestmark_integration
def test_a_configured_credential_still_works_alongside_issued_ones(live, monkeypatch):
    """Config is not replaced, and is checked first — it is the path that still works when the
    store is down, so an estate that has not adopted enrolment is unaffected by this change."""
    client = _client(
        monkeypatch,
        live.app.state.settings.database_url,
        tenant_tokens=f'{{"{TENANT_B}": "configured-token"}}',
    )
    with client:
        assert client.get("/whoami", headers={"Authorization": "Bearer configured-token"}).json() == {
            "kind": "tenant",
            "tenant_id": TENANT_B,
        }
