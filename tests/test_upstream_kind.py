# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Phase 2 of the MCP-passthrough plan — the entity model.

A remote MCP server is registered as a ``DeviceConfig``, not a new entity type, discriminated
by two fields: ``upstream_kind`` (what the upstream *speaks*) and ``upstream_transport``
(how we *talk* to it). Reusing the device entity is the decision that keeps a future
multitenancy retrofit to one set of keys, routes and metrics instead of two.

Two things can go wrong here, and neither is caught by a happy-path round-trip:

1. **Adding a field to a persisted record breaks the records already stored.** A Redis hash
   written before this change has no ``upstream_kind`` key, and a SQLite ``devices`` table
   created before it has no such column — so an ``INSERT`` naming that column fails outright.
   An existing embedded deployment would come back up unable to save a device. Both are
   tested against a genuinely pre-upgrade artefact rather than a freshly built one.
2. **``transport`` gets overloaded.** It is *inbound* — how the pod serves MCP to its
   clients — and ``api/sse.py`` hard-rejects anything but ``"sse"``. A proxied upstream must
   keep ``transport="sse"``; ``upstream_transport`` is the separate outbound field. Conflating
   them looks harmless right up to the point where a registered MCP upstream cannot be
   connected to at all.
"""

from __future__ import annotations

import sqlite3

import pytest

from device_mcp_gateway.schemas import DeviceDetail, DeviceSummary
from device_mcp_gateway.shared.registry_backend import DeviceConfig
from device_mcp_gateway.storage.sqlite_store import SqliteDeviceStore

# The devices table exactly as it existed before this change. Written out rather than
# imported so it keeps describing the *old* shape when the real DDL moves on.
_PRE_UPGRADE_DDL = """
CREATE TABLE devices (
    hostname       TEXT PRIMARY KEY,
    base_url       TEXT NOT NULL,
    spec_url       TEXT,
    transport      TEXT NOT NULL DEFAULT 'sse',
    auth_type      TEXT,
    auth_config    TEXT,
    rate_limit_rps REAL
)
"""


# --- the entity model --------------------------------------------------------


def test_a_device_defaults_to_an_openapi_upstream():
    """Every device registered before passthrough existed is an OpenAPI upstream, so that
    has to be what the defaults say — a record with no opinion must not become 'mcp'."""
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1")
    assert cfg.upstream_kind == "openapi"
    assert cfg.upstream_transport == "http"


def test_upstream_transport_is_not_the_inbound_transport():
    """``transport`` is how the pod serves its clients; ``upstream_transport`` is how the pod
    reaches the upstream. A proxied MCP server is still served to clients over SSE."""
    cfg = DeviceConfig(
        hostname="dev1",
        base_url="http://dev1/mcp",
        upstream_kind="mcp",
        upstream_transport="http",
    )
    assert cfg.transport == "sse", "the inbound transport must be unaffected by the upstream kind"
    assert cfg.upstream_transport == "http"


# --- persistence: records written before this change --------------------------


def test_a_redis_hash_written_before_this_change_loads_as_openapi():
    """HGETALL on a pre-upgrade device returns a hash with no upstream keys at all. It must
    reconstruct as an OpenAPI device, not raise and not silently become something else."""
    pre_upgrade = {
        "hostname": "dev1",
        "base_url": "http://dev1",
        "transport": "sse",
        "spec_url": "http://dev1/openapi.json",
        "auth_type": "api_key",
        "auth_config": "ciphertext",
        "rate_limit_rps": "5.0",
        "spec_hash": "abc",
        "pod_active": "True",
        "reachable": "True",
        "last_check": "1234.5",
        "spawn_error": "",
        "worker_id": "w1",
        "tools_revision": "3",
    }
    cfg = DeviceConfig.from_redis_hash(pre_upgrade)
    assert cfg.upstream_kind == "openapi"
    assert cfg.upstream_transport == "http"
    assert cfg.tools_revision == 3  # the rest of the record is untouched


def test_redis_hash_round_trip_preserves_an_mcp_upstream():
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1/mcp", upstream_kind="mcp", upstream_transport="http")
    back = DeviceConfig.from_redis_hash(cfg.to_redis_hash())
    assert (back.upstream_kind, back.upstream_transport) == ("mcp", "http")
    assert back.transport == "sse"


def test_an_empty_upstream_value_falls_back_rather_than_persisting_an_empty_kind():
    """``to_redis_hash`` writes "" for an unset value, and a half-written hash is a real
    possibility. An empty kind must read back as the default, never as ""; an empty string
    would fail every ``upstream_kind == "openapi"`` branch and route the device nowhere."""
    h = DeviceConfig(hostname="dev1", base_url="http://dev1").to_redis_hash()
    h["upstream_kind"] = ""
    h["upstream_transport"] = ""
    cfg = DeviceConfig.from_redis_hash(h)
    assert (cfg.upstream_kind, cfg.upstream_transport) == ("openapi", "http")


@pytest.mark.asyncio
async def test_sqlite_database_created_before_this_change_still_accepts_writes(tmp_path):
    """The migration trap. ``CREATE TABLE IF NOT EXISTS`` is a no-op against an existing
    table, so adding a column to the DDL does nothing for a database already on disk — and
    the next INSERT naming that column fails with "no such column". An embedded deployment
    would upgrade cleanly and then be unable to register anything.
    """
    db = str(tmp_path / "pre_upgrade.db")
    with sqlite3.connect(db) as conn:  # a database from the previous version
        conn.execute(_PRE_UPGRADE_DDL)
        conn.execute("INSERT INTO devices (hostname, base_url, transport) VALUES ('legacy', 'http://legacy', 'sse')")

    store = SqliteDeviceStore(db_path=db)
    await store.initialize()

    # The pre-existing row reads back as an OpenAPI device...
    rows = {r["hostname"]: r for r in await store.load_all()}
    assert rows["legacy"]["upstream_kind"] == "openapi"
    assert rows["legacy"]["upstream_transport"] == "http"

    # ...and a new MCP upstream can still be written to the migrated table.
    await store.save(
        "proxied",
        {
            "base_url": "http://remote/mcp",
            "spec_url": None,
            "transport": "sse",
            "auth_type": None,
            "auth_config": None,
            "rate_limit_rps": None,
            "upstream_kind": "mcp",
            "upstream_transport": "http",
        },
    )
    rows = {r["hostname"]: r for r in await store.load_all()}
    assert rows["proxied"]["upstream_kind"] == "mcp"
    assert rows["proxied"]["transport"] == "sse"


@pytest.mark.asyncio
async def test_sqlite_save_defaults_a_record_that_omits_the_upstream_fields(tmp_path):
    """Callers that predate passthrough pass a record with no upstream keys."""
    store = SqliteDeviceStore(db_path=str(tmp_path / "d.db"))
    await store.initialize()
    await store.save(
        "dev1",
        {"base_url": "http://dev1", "spec_url": None, "transport": "sse", "auth_type": None, "auth_config": None},
    )
    row = (await store.load_all())[0]
    assert row["upstream_kind"] == "openapi"
    assert row["upstream_transport"] == "http"


# --- API surface --------------------------------------------------------------


def test_the_discriminator_is_visible_on_both_read_projections():
    """A client cannot tell an MCP upstream from an OpenAPI one without this, and the list
    view is exactly where an operator would look first."""
    cfg = DeviceConfig(hostname="dev1", base_url="http://dev1/mcp", upstream_kind="mcp")
    assert DeviceSummary.from_config(cfg).upstream_kind == "mcp"
    detail = DeviceDetail.from_config(cfg)
    assert detail.upstream_kind == "mcp"
    assert detail.upstream_transport == "http"


def _register(client, hostname, **extra):
    body = {"hostname": hostname, "base_url": "http://192.0.2.99", "auth_type": "none"}
    body.update(extra)
    return client.post("/v1/devices", json=body)


def test_an_unknown_upstream_kind_is_refused(client):
    resp = _register(client, "uk-bad-kind", upstream_kind="graphql")
    assert resp.status_code == 400
    assert "upstream_kind" in resp.json()["detail"]


def test_an_unknown_upstream_transport_is_refused(client):
    resp = _register(client, "uk-bad-transport", upstream_kind="mcp", upstream_transport="stdio")
    assert resp.status_code == 400
    assert "upstream_transport" in resp.json()["detail"]


def test_sse_upstream_transport_is_a_known_value_but_refused_in_v1(client):
    """The value space is fixed now so the field never has to widen later, but only
    Streamable HTTP is implemented. The distinct message is the point: a caller must be able
    to tell "not a real option" from "not yet"."""
    resp = _register(client, "uk-sse-upstream", upstream_kind="mcp", upstream_transport="sse")
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "sse" in detail and "not yet supported" in detail.lower()


def test_an_openapi_device_may_not_declare_an_upstream_transport(client):
    """``upstream_transport`` is meaningless for a translated OpenAPI device. Accepting it
    silently would leave a stored value that reads as configuration and does nothing."""
    resp = _register(client, "uk-openapi-transport", upstream_transport="sse")
    assert resp.status_code == 400


def test_an_mcp_upstream_may_not_carry_a_spec_url(client):
    """A proxied MCP server has no OpenAPI document. A spec_url here means the caller has
    confused the two modes, and accepting it would start a translation that can never work."""
    resp = _register(client, "uk-mcp-spec", upstream_kind="mcp", spec_url="http://192.0.2.99/openapi.json")
    assert resp.status_code == 400
    assert "spec_url" in resp.json()["detail"]


def test_the_inbound_transport_is_still_restricted_to_sse(client):
    """Guards the overload directly: adding an outbound transport field must not make the
    inbound one negotiable."""
    resp = _register(client, "uk-inbound", transport="http")
    assert resp.status_code == 400
    assert "Transport" in resp.json()["detail"]


def test_registering_an_mcp_upstream_is_accepted_as_a_value_but_not_yet_served(client):
    """Phase 2 fixes the entity model; Phase 3 makes it work. Until the proxy pod exists the
    gateway must refuse rather than accept an MCP upstream and quietly treat it as OpenAPI —
    a device that registers successfully and then never serves a tool is the worse failure.

    This test flips in Phase 3, which is deliberate: it is the reminder to remove the gate.
    """
    resp = _register(client, "uk-mcp-live", upstream_kind="mcp")
    assert resp.status_code == 501
    assert "not yet" in resp.json()["detail"].lower()


def test_an_ordinary_registration_is_unaffected_and_reports_openapi(client):
    resp = _register(client, "uk-plain")
    try:
        assert resp.status_code == 200
        device = resp.json()["device"]
        assert device["upstream_kind"] == "openapi"
        assert device["upstream_transport"] == "http"
        assert device["transport"] == "sse"
    finally:
        client.delete("/v1/devices/uk-plain")


def test_update_preserves_the_upstream_kind_when_the_put_omits_it(client, mock_target_url):
    """A PUT that says nothing about the upstream must not reset it to the default — the
    same class of bug as the PUT-wipes-credentials regression."""
    client.post("/v1/devices", json={"hostname": "uk-put", "base_url": mock_target_url, "auth_type": "none"})
    try:
        resp = client.put("/v1/devices/uk-put", json={"base_url": mock_target_url, "auth_type": "none"})
        assert resp.status_code == 200
        assert resp.json()["device"]["upstream_kind"] == "openapi"
    finally:
        client.delete("/v1/devices/uk-put")
