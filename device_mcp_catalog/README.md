# device-mcp-catalog

The provider-plane device catalog ([ADR-0020](../docs/adr/0020-the-device-catalog.md)):
device-type curation and per-tenant assignment. A tenant **claims** an assigned device type
into their own gateway registry via the gateway's ordinary `POST /v1/devices` route — this
service never holds a tenant credential, a claim, or a device instance (ADR-0020 §5).

Deliberately a separate process from the console BFF, with its own PostgreSQL database
(ADR-0020 §7, ADR-0025) — not a client library bolted onto an existing one. See
`docs/adr/0020-the-device-catalog.md` and `docs/adr/0025-the-catalog-has-its-own-durability-story.md`
in the parent repo for the design this implements.

## Local development

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
CATALOG_DATABASE_URL=postgresql://postgres:test@localhost:5432/catalog_dev pytest
```

Tests that need a real Postgres are marked `integration` and skip (not fail) when
`CATALOG_TEST_DATABASE_URL` (default `postgresql://postgres:test@localhost:55432/catalog_test`)
is unreachable — there is no fake/in-memory double for this store.

## API (device-type curation, ADR-0020 §1)

Every route below requires `Authorization: Bearer $CATALOG_API_TOKEN` — this service has
exactly one caller in phase 1 (the console BFF), so a shared token gates all of it rather
than a scope model with no second caller yet to justify it.

- `POST /device-types` — create a device type and its version 1.
- `POST /device-types/{id}/versions` — add the next version (monotonic, immutable once created).
- `GET /device-types` — list types with each one's latest version number.
- `GET /device-types/{id}` — one type's full version history.

A device type is a **template only**: no host, no credential, no tenant. `spec_path` (openapi
devices only) is relative to whatever `base_url` a tenant supplies at claim time — the type
names the appliance model, never an instance's address.
