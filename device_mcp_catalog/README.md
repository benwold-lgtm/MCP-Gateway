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
