# RBAC — scopes, roles, and IdP mapping

The gateway authorizes on **scopes**, not role strings. Roles are named **bundles of
scopes** ([rbac.py](../device_mcp_gateway/rbac.py) `ROLE_SCOPES`); routes only ever call
`require_scope(...)`, so adding a role never touches a route. This is the living reference
for the role/scope model; the *decision* behind it is
[ADR-0007](adr/0007-federated-identity-oidc-and-gateway-rbac.md).

## Scopes (the atoms)

| Scope | Grants | Route guards (examples) |
|-------|--------|--------------------------|
| `devices:read` | See devices and their state | `GET /v1/devices`, `GET /v1/devices/{h}`, `…/diagnostics`, `…/tools`, `…/tools/diff`, `…/deadletter` (inspect), `GET /v1/admin/overview` |
| `devices:write` | Manage the fleet | `POST/PUT/DELETE /v1/devices/{h}`, `POST …/deadletter/replay`, `DELETE …/deadletter` (drain) |
| `tools:call` | Invoke a device's MCP tools | `GET /v1/devices/{h}/sse`, `POST /v1/devices/{h}/messages` |
| `metrics:read` | Read operational metrics | `GET /v1/metrics/summary` |

> `/health`, `/livez`, `/readyz` and the Prometheus scrape port are unauthenticated infra
> contracts and are not scope-gated.

## Roles (scope bundles)

Two kinds of principal: **humans** operating the UI, and **machines** (an MCP client/agent
invoking tools over SSE). One scope model serves both.

| Role | `devices:read` | `devices:write` | `tools:call` | `metrics:read` | For |
|------|:---:|:---:|:---:|:---:|-----|
| **admin** | ✅ | ✅ | ✅ | ✅ | Full control (human) |
| **operator** | ✅ | ✅ | — | ✅ | Onboard / edit / remove devices, manage the dead-letter queue — but not invoke tools (human) |
| **viewer** | ✅ | — | — | ✅ | Read-only (human) — *current `viewer`* |
| **auditor** | — | — | — | ✅ | Observability / compliance, no device access (human). Widens to `audit:read` when that scope exists |
| **caller** (agent) | ✅ | — | ✅ | — | An MCP client/agent that discovers and invokes tools — **machine identity**, not a UI role |

`admin` and `viewer` exist today; `operator`, `auditor`, and `caller` are the seed additions
from ADR-0007. Add a role by adding one entry to `ROLE_SCOPES` — no route changes.

## Where roles come from

### Federated (OIDC) — production
The IdP asserts **group membership** in a token claim (`groups` or `roles`); a
**`group → role/scopes` mapping in gateway config** is the single source of truth. The UI
reflects whatever scopes the gateway grants (via `/auth/me`), so UI and gateway permissions
can't drift. Illustrative config (final shape TBD in implementation):

```yaml
auth:
  oidc:
    issuer: https://login.example.com/realms/corp   # ADFS / Entra / Okta / Keycloak …
    audience: device-mcp-gateway
    groups_claim: groups
    group_roles:                # IdP group  → gateway role (a scope bundle)
      mcp-admins:    admin
      mcp-operators: operator
      mcp-viewers:   viewer
      mcp-auditors:  auditor
```

A user in multiple groups gets the **union** of the mapped scopes.

### Local static keys — bootstrap, CI/test, break-glass
Independent of any IdP and always available (ADR-0007): `MCP_ADMIN_KEY` / `MCP_VIEWER_KEY`,
or an explicit `gateway.rbac: [{name, key, role}]` list. These keep working when the IdP is
unreachable — keep at least one admin key as documented **break-glass**.

## Future granularity

The scope set is the granularity lever; all of this is additive (no route churn):

- Split `devices:write` → `devices:create` / `devices:update` / `devices:delete`.
- Add `deadletter:manage` (separate DLQ recovery from general writes), `audit:read`.
- **Resource-/tenant-scoped** grants (e.g. `operator@tenant-a`) — the natural extension if
  multi-tenancy ([ADR-0004](adr/0004-single-tenant-per-stack.md)) resumes; the OIDC
  claim→scope mapping is designed to carry a tenant dimension even while unused.
