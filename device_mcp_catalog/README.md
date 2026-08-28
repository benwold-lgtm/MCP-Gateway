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

## Callers (ADR-0020 §7a)

Every route requires `Authorization: Bearer <token>`, and **which token decides what the
caller may do and, for a tenant, which tenant it is**:

| Caller | Configured as | May |
|---|---|---|
| Provider console | `CATALOG_API_TOKEN` | curate, assign and revoke, read everything |
| A tenant's console | one entry in `CATALOG_TENANT_TOKENS`, a JSON `{tenant_id: token}` map | read the types assigned **to it**, record claims **for itself** |

Two rules follow, and the routes below are written assuming them:

* **The tenant comes from the credential, never from the request.** A `tenant_id` in a path or
  a body is a client assertion. A tenant caller that names anyone but itself is refused with
  `403` — never filtered to an empty result, never rewritten to its own tenant.
* **A tenant caller cannot see the unscoped catalog.** `GET /device-types` is provider-only;
  for a tenant, the type list *is* the assignment list.

A malformed caller table — a tenant token equal to the provider's, or shared between two
tenants — **refuses startup**. Unlike an unreachable database, which this service stays up to
report as a named condition, an ambiguous credential does not fail to answer: it answers as
the wrong caller.

`GET /whoami` returns `{kind, tenant_id}` for the presented credential. It exists so a tenant
console can verify on startup that it was not handed the provider's token — the one
misconfiguration this service cannot detect from its own side, since that request is a
perfectly valid provider request.

## API (device-type curation, ADR-0020 §1)

Provider-only (see Callers above).

- `POST /device-types` — create a device type and its version 1.
- `POST /device-types/{id}/versions` — add the next version (monotonic, immutable once created).
- `GET /device-types` — list types with each one's latest version number.
- `GET /device-types/{id}` — one type's full version history.

A device type is a **template only**: no host, no credential, no tenant. `spec_path` (openapi
devices only) is relative to whatever `base_url` a tenant supplies at claim time — the type
names the appliance model, never an instance's address.

## API (assignment, ADR-0020 §2)

Assignment is an offer, written here only — it never reaches a tenant's registry. Assigning
and revoking are provider-only; reading a tenant's assignments is available to that tenant's
own credential as well.

- `POST /device-types/{id}/assign` (`{tenant_id, assigned_by}`) — offer a type to a tenant.
  Idempotent: assigning an already-active pair returns the existing assignment rather than
  erroring or minting a second one.
- `DELETE /device-types/{id}/assign/{tenant_id}` — revoke. `404` if nothing is actively
  assigned. A later re-assign of the same pair inserts a new row rather than reviving the
  old one, so the full assign/revoke history is retained (ADR-0025), not overwritten.
- `GET /tenants/{tenant_id}/assignments` — the device types currently (not historically)
  assigned to a tenant. This is what the tenant's claim view (slice 4) reads.

## API (claim recording, ADR-0020 §4)

The claim itself happens entirely in the console BFF, against the gateway's own
`POST /devices` — this service is never in that call path and never sees a tenant credential.
The one thing recorded here is which curated version a now-registered device came from, so
slice 5's upgrade-offer diff has a baseline.

- `POST /device-types/{id}/claims` (`{tenant_id, hostname, version}`) — pin a device to the
  curated version it was registered from. `404` if that `(id, version)` pair was never
  curated. Re-claiming the same `(tenant_id, hostname)` (a delete + re-register) replaces the
  pin rather than accumulating a second row for it.

## API (upgrade offers, ADR-0020 §4, slice 5)

Never blocking, never scheduled, never forced. A version's `tool_set` — an optional list of
`{"name", "method", "schema"}` dicts, DECLARED by the curator at `POST /device-types` /
`POST /device-types/{id}/versions` time — is diffed against a claimed device's pinned
version using a small pure classifier (`tool_diff.py`, a deliberate duplicate of
`device_mcp_gateway.core.manifest_diff`'s `diff_tools`, kept separate so this service isn't
pulled into the gateway package's dependency tree — see that module's docstring). Nothing
here is a live measurement: the catalog has no tenant `base_url` to fetch a real spec with,
so `tool_set` is exactly as trustworthy as the curator who entered it.

- `GET /tenants/{tenant_id}/upgrades` — one entry per claimed device whose pinned version
  differs from the type's current curated version. `diff` is `null` when either version has
  no declared `tool_set` — a distinct condition from an empty (diffed, no changes) result.
  Accepting an offer is just re-calling `POST /device-types/{id}/claims` with the new
  version; there is no separate "apply" route.
