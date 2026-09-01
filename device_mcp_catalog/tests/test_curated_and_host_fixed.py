# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §4a/§4b/§4c — the two write-time facts a curator may now declare about a type.

Both sections add a *curated fact about a product* that used to be the tenant's to supply or
guess: §4a/§4b a snapshotted spec document, §4c the address when it is genuinely provider
knowledge. They are tested together because they are one capability and their validators are
siblings — written in one pass on purpose, since two written months apart from the same
reasoning rediscovered do not agree (ADR-0020 §4c, closing note).

Every refusal here is asserted as a **refusal, not a silent normalisation**. That is the whole
design position: a curated field that quietly does nothing is one a curator believes is in
effect, and a row that can hold a contradictory pair is a state a future bug reaches
accidentally and then fails quietly inside.

Real Postgres, skipped when unreachable — this store has no in-memory double by design.
"""

from __future__ import annotations

import hashlib
import json

import asyncpg
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from device_mcp_catalog.app.main import create_app

pytestmark = pytest.mark.integration

API_TOKEN = "test-token"

DOCUMENT = json.dumps({"openapi": "3.0.3", "info": {"title": "Acme", "version": "1"}, "paths": {}})


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(database_url):
    try:
        conn = await asyncpg.connect(database_url)
    except Exception:
        pytest.skip(f"real Postgres not reachable at {database_url}")
    try:
        await conn.execute("TRUNCATE device_type_versions, device_types CASCADE")
    except asyncpg.UndefinedTableError:
        pass
    finally:
        await conn.close()


def _client(monkeypatch, database_url) -> TestClient:
    monkeypatch.setenv("CATALOG_DATABASE_URL", database_url)
    monkeypatch.setenv("CATALOG_API_TOKEN", API_TOKEN)
    return TestClient(create_app())


def _auth() -> dict:
    return {"Authorization": f"Bearer {API_TOKEN}"}


def _plan(**over) -> dict:
    plan = {"slug": "acme-sensor-x1", "name": "Acme Sensor X1", "upstream_kind": "openapi"}
    plan.update(over)
    return plan


def _create(client, **over):
    return client.post("/device-types", headers=_auth(), json=_plan(**over))


# --- §4a: the document is stored, and stored as the bytes that were curated ---------------


def test_a_curated_document_is_snapshotted_onto_the_version(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, curated_document=DOCUMENT)
    assert resp.status_code == 201, resp.text
    version = resp.json()["versions"][0]
    assert version["curated_document"] == DOCUMENT


def test_the_document_comes_back_byte_for_byte(monkeypatch, database_url):
    """§4b recomputes a hash from these bytes and refuses to trust the stored one. If the
    store normalised key order or whitespace — as JSONB would — the recompute would disagree
    with the assertion on every single claim, and a check that always fails gets deleted.

    The document below is deliberately not in the shape `json.dumps` would produce from a
    round-trip: keys out of alphabetical order, odd spacing, a trailing newline.
    """
    awkward = '{"openapi":"3.0.3",\n  "paths": {},\n "info":{"version":"1","title":"Acme"}}\n'
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, curated_document=awkward)
    assert resp.json()["versions"][0]["curated_document"] == awkward


def test_the_asserted_hash_is_of_those_bytes(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, curated_document=DOCUMENT)
    version = resp.json()["versions"][0]
    assert version["curated_document_sha256"] == hashlib.sha256(DOCUMENT.encode()).hexdigest()


def test_a_curator_cannot_assert_a_hash_that_disagrees_with_their_content(monkeypatch, database_url):
    """The hash is computed, never accepted. A caller able to supply one could make the
    stored pair agree by construction, which would leave §4b's claim-time recompute verifying
    nothing on arrival — the drift it exists to catch is a *later* one."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, curated_document=DOCUMENT, curated_document_sha256="0" * 64)
    assert resp.status_code == 201
    version = resp.json()["versions"][0]
    assert version["curated_document_sha256"] == hashlib.sha256(DOCUMENT.encode()).hexdigest()


def test_no_document_means_no_hash(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, spec_path="/openapi.json")
    assert resp.json()["versions"][0]["curated_document_sha256"] is None


# --- §4b: one spec source, resolved by the curator or not at all --------------------------


def test_a_document_and_a_spec_path_together_are_refused(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, curated_document=DOCUMENT, spec_path="/openapi.json")
    assert resp.status_code == 400
    assert "never both" in resp.json()["detail"]


def test_neither_source_silently_wins(monkeypatch, database_url):
    """Named separately from the refusal above because the tempting fix is a precedence rule,
    and a precedence rule is the failure mode: nothing is written at all."""
    with _client(monkeypatch, database_url) as client:
        assert _create(client, curated_document=DOCUMENT, spec_path="/openapi.json").status_code == 400
        listed = client.get("/device-types", headers=_auth()).json()
    assert listed["device_types"] == []


def test_a_declared_tool_set_beside_a_document_is_refused(monkeypatch, database_url):
    """`tool_set` justifies being unverified by "the catalog has no base_url to fetch a live
    spec against". That premise is false the moment content is in the row — the §7a shape,
    a written precondition quietly becoming untrue — so the pair is refused rather than
    stored."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, curated_document=DOCUMENT, tool_set=[{"name": "get_status", "method": "GET"}])
    assert resp.status_code == 400
    assert "tool_set" in resp.json()["detail"]


def test_a_declared_tool_set_is_still_fine_without_a_document(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, spec_path="/openapi.json", tool_set=[{"name": "get_status", "method": "GET"}])
    assert resp.status_code == 201
    assert resp.json()["versions"][0]["tool_set"] == [{"name": "get_status", "method": "GET"}]


def test_the_exclusivity_holds_on_a_later_version_too(monkeypatch, database_url):
    """`add_version` is the second write path. A check wired into creation only would leave
    the constraint reachable by the ordinary way a type evolves."""
    with _client(monkeypatch, database_url) as client:
        created = _create(client, spec_path="/openapi.json")
        type_id = created.json()["id"]
        resp = client.post(
            f"/device-types/{type_id}/versions",
            headers=_auth(),
            json={"upstream_kind": "openapi", "curated_document": DOCUMENT, "spec_path": "/openapi.json"},
        )
    assert resp.status_code == 400


# --- §4c: who supplies the address ---------------------------------------------------------


def test_a_type_defaults_to_the_tenant_supplying_the_address(monkeypatch, database_url):
    """Every version curated before §4c existed is this, and the column's default has to
    agree with the model's or a migrated row reads differently than a new one."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, spec_path="/openapi.json")
    version = resp.json()["versions"][0]
    assert version["host_source"] == "tenant"
    assert version["fixed_base_url"] is None


def test_a_host_fixed_type_carries_the_address(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, host_source="provider_fixed", fixed_base_url="https://svc.provider.example")
    assert resp.status_code == 201, resp.text
    version = resp.json()["versions"][0]
    assert version["host_source"] == "provider_fixed"
    assert version["fixed_base_url"] == "https://svc.provider.example"


def test_a_host_fixed_type_with_no_address_is_refused(monkeypatch, database_url):
    """Discovered by the curator, at write time — not by a tenant, at claim time, against a
    type that declares a fixed host and has none."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, host_source="provider_fixed")
    assert resp.status_code == 400
    assert "fixed_base_url is required" in resp.json()["detail"]


def test_an_address_under_tenant_sourcing_is_refused_not_ignored(monkeypatch, database_url):
    """The other direction, and the one that would otherwise pass silently. A curator who
    filled in an address believes it is in effect; storing it under `host_source == 'tenant'`,
    where nothing reads it, is exactly the condition the api-key validator already refuses."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, fixed_base_url="https://svc.provider.example")
    assert resp.status_code == 400
    assert "must not be set" in resp.json()["detail"]


def test_host_fixing_says_nothing_about_the_credential(monkeypatch, database_url):
    """§4c's entire point: a host-fixed type is not a §6 provider-operated service. The
    provider knows the address; the tenant still brings their own key, and §5 is untouched."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(
            client,
            host_source="provider_fixed",
            fixed_base_url="https://svc.provider.example",
            auth_kind="api_key",
            api_key_location="header",
            api_key_name="X-Acme-Key",
        )
    assert resp.status_code == 201, resp.text
    version = resp.json()["versions"][0]
    assert version["auth_kind"] == "api_key" and version["api_key_name"] == "X-Acme-Key"
    # Nothing resembling a credential value is curated, in either direction.
    assert "api_key" not in {k for k, v in version.items() if isinstance(v, str) and v.startswith("secret")}


def test_an_unknown_host_source_is_refused_by_the_model(monkeypatch, database_url):
    with _client(monkeypatch, database_url) as client:
        resp = _create(client, host_source="provider_maybe", fixed_base_url="https://x.example")
    assert resp.status_code == 422


def test_the_two_declarations_are_independent(monkeypatch, database_url):
    """A host-fixed type with a curated document is a legitimate combination — the provider
    knows both the address and the shape — and neither validator may object to the other."""
    with _client(monkeypatch, database_url) as client:
        resp = _create(
            client,
            host_source="provider_fixed",
            fixed_base_url="https://svc.provider.example",
            curated_document=DOCUMENT,
        )
    assert resp.status_code == 201, resp.text
    version = resp.json()["versions"][0]
    assert version["fixed_base_url"] == "https://svc.provider.example"
    assert version["curated_document"] == DOCUMENT


# --- the table's own guard, independent of the repo's ---------------------------------------


@pytest.mark.asyncio
async def test_the_database_refuses_the_pair_the_repo_refuses(real_db):
    """Deliberate overlap. `_check_host_source` raises first with a message a curator can act
    on; the CHECK constraint is what holds if a future write path forgets to call it. A guard
    reachable only through one function is a guard on that function, not on the data.
    """
    async with real_db.pool.acquire() as conn:
        type_id = await conn.fetchval(
            "INSERT INTO device_types (id, slug, name) VALUES (gen_random_uuid(), 'x-1', 'X') RETURNING id"
        )
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO device_type_versions (id, device_type_id, version, host_source, fixed_base_url)
                VALUES (gen_random_uuid(), $1, 1, 'tenant', 'https://svc.provider.example')
                """,
                type_id,
            )


@pytest.mark.asyncio
async def test_the_database_refuses_two_spec_sources(real_db):
    async with real_db.pool.acquire() as conn:
        type_id = await conn.fetchval(
            "INSERT INTO device_types (id, slug, name) VALUES (gen_random_uuid(), 'x-2', 'X') RETURNING id"
        )
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO device_type_versions
                    (id, device_type_id, version, spec_path, curated_document)
                VALUES (gen_random_uuid(), $1, 1, '/openapi.json', $2)
                """,
                type_id,
                DOCUMENT,
            )
