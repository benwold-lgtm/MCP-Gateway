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
| `backup:read` | Export an archive of the registry | `GET /v1/admin/backup`, `POST /v1/admin/backup` |
| `backup:write` | Restore an archive | `POST /v1/admin/restore` |
| `backup:export-portable` | **Additionally** export a *portable* archive — credentials re-encrypted to a passphrase instead of the stack key | `POST /v1/admin/backup` with `kind=portable` |

> **`backup:read` is not a read-only grant in the ordinary sense.** An archive contains
> every device's `base_url`, spec URL and configuration, plus its credentials as
> ciphertext. Treat it like `devices:read` over the whole fleet at once, and see
> [ADR-0011](adr/0011-backup-and-restore.md).
>
> **`backup:export-portable` is never implied by the other two.** A portable archive is a
> complete set of live device credentials behind a single passphrase, so it is
> key-independent by design — that is what makes it useful for migration and dangerous to
> hold standing permission for. It is checked *inside* the handler, because whether it is
> required depends on the requested `kind`.

> `/health`, `/livez`, `/readyz` and the Prometheus scrape port are unauthenticated infra
> contracts and are not scope-gated.
>
> `GET /v1/auth/me` requires authentication but **no specific scope** — it returns the
> caller's own `subject`, effective `scopes`, and `auth_method`. A UI/BFF reads it to gate
> views on the gateway's scopes (so the two never drift); see "Where roles come from" below.

## Roles (scope bundles)

Two kinds of principal: **humans** operating the UI, and **machines** (an MCP client/agent
invoking tools over SSE). One scope model serves both.

| Role | `devices:read` | `devices:write` | `tools:call` | `metrics:read` | `backup:read` | `backup:write` | `backup:export-portable` | For |
|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|-----|
| **admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Full control (human) |
| **operator** | ✅ | ✅ | — | ✅ | — | — | — | Onboard / edit / remove devices, manage the dead-letter queue — but not invoke tools (human) |
| **viewer** | ✅ | — | — | ✅ | — | — | — | Read-only (human) — *current `viewer`* |
| **auditor** | — | — | — | ✅ | — | — | — | Observability / compliance, no device access (human). Widens to `audit:read` when that scope exists |
| **caller** (agent) | ✅ | — | ✅ | — | — | — | — | An MCP client/agent that discovers and invokes tools — **machine identity**, not a UI role |
| **backup** (agent) | — | — | — | — | ✅ | ✅ | — | A scheduled backup/restore job — **machine identity**. Deliberately not `admin`: a nightly cron entry should not also be able to invoke tools or edit the fleet, and the portable archive stays an explicit operator action rather than a standing grant |

All six roles are defined in [`ROLE_SCOPES`](../device_mcp_gateway/rbac.py) today
(`operator`/`auditor`/`caller` were added with the OIDC work, ADR-0007; `backup` with
ADR-0011). Add a role by adding one entry to `ROLE_SCOPES` — no route changes.

Note that `operator` does **not** get the backup scopes even though it manages the fleet:
one call as `backup:read` yields every device's configuration in a single file, which is a
different exposure from editing devices one at a time.

## Where roles come from

### Federated (OIDC) — production
The IdP asserts **group membership** in a token claim (`groups` or `roles`); a
**`group → role/scopes` mapping in gateway config** is the single source of truth. The UI
reflects whatever scopes the gateway grants (via `/auth/me`), so UI and gateway permissions
can't drift. Config lives under `gateway.oidc` (alongside the static-key settings), wired by
[oidc.py](../device_mcp_gateway/oidc.py):

```yaml
gateway:
  oidc:
    enabled: true
    issuer: https://login.example.com/realms/corp   # ADFS / Entra / Okta / Keycloak …
    audience: device-mcp-gateway                     # must equal the JWT 'aud'
    groups_claim: groups
    algorithms: ["RS256"]       # asymmetric allow-list; HS*/none are refused
    group_roles:                # IdP group  → gateway role (a scope bundle)
      mcp-admins:    admin
      mcp-operators: operator
      mcp-viewers:   viewer
      mcp-auditors:  auditor
```

A user in multiple groups gets the **union** of the mapped scopes. A valid token whose groups
map to **no** role authenticates with an **empty scope set** — every route then 403s, and the
audit shows *who* was denied. `jwks_uri` is auto-discovered from the issuer unless set
explicitly; the full knob list is in [config.yaml](../config.yaml).

The audit subject is `oidc:{issuer}#{sub}`. The issuer is part of the identity because `sub`
is unique *within* an issuer, not globally — which matters as soon as there is more than one.

#### More than one issuer (ADR-0013 §6)

A tenant gateway can additionally trust the **provider IdP**, so a support engineer acts as
themselves in the tenant's audit chain rather than behind a shared admin key. Use `issuers`
instead of the single-issuer keys — setting both is refused at startup:

```yaml
gateway:
  oidc:
    enabled: true
    issuers:
      - issuer: https://login.example.com/realms/corp
        audience: device-mcp-gateway
        plane: tenant
        group_roles:
          mcp-admins: admin
      - issuer: https://provider-idp.example.com
        audience: device-mcp-gateway
        plane: provider
        group_roles:
          provider-support: operator
```

Three rules, each of which exists because its absence fails **silently** — the token still
validates and the request still succeeds:

| Rule | Without it |
|---|---|
| The issuer is resolved from `iss` **first**, and the decode is pinned to that one issuer with only that issuer's keys | A token signed by issuer A's key while claiming `iss: B` is accepted — a tenant IdP operator mints themselves provider identity on their own gateway |
| `group_roles` is **per issuer**, with no shared or fallback mapping | A tenant's own IdP admin creates a group named whatever the provider mapping keys on, adds themselves, and their gateway grants them provider-level scopes |
| `plane` caps the scopes reachable from an issuer, **server-side** | The console's login-time plane-fixing is a session-flow guarantee; a minted provider token replayed straight at this API bypasses it entirely |

The **provider** plane is capped at `devices:read`, `devices:write`, `metrics:read`. It can
never reach `tools:call` — invoking a tool actuates the customer's real hardware, and routine
debugging should not carry that ambiently — nor any `backup:*` scope, because the provider
holds `MCP_SECRET_KEY` and so a ciphertext archive is as much a credential dump as a portable
one. A provider group mapped to a role that exceeds the cap is refused at startup. The
**tenant** plane has no cap: a tenant's own administrator legitimately holds everything on
their own stack.

#### Lifting the cap for one request — elevated grants (ADR-0013 §11)

The cap is what makes provider access everyday debugging rather than standing authority, so
it also blocks the two operations that sometimes genuinely need to happen: invoking a tool,
and touching backups. Those arrive as an **elevated grant** — a claim on the token, minted by
the provider IdP after a step-up, raising that issuer's cap for **that request only**:

```yaml
gateway:
  tenant_id: acme                        # which tenant this stack is; required for a
  oidc:                                  # provider-plane issuer, refused at startup without
    issuers:
      - issuer: https://provider-idp.example.com
        plane: provider
        step_up_acr: ["urn:mcp:provider:step-up"]
        grant_claim: mcp_grant           # default; namespaced names are common
        group_roles:
          provider-support: operator
```

```json
{"id": "g-7f2", "tenant": "acme", "scopes": ["tools:call"], "exp": 1755200000}
```

What is worth knowing operationally:

- **`tools:call` grants last 900s and are replayable inside that window** (a debugging session
  is several calls); **`backup:*` grants are single-use**, consumed in this gateway's Redis.
  A grant naming both is single-use and takes the shorter window.
- **The window is the gateway's, measured from the token's `auth_time`.** A claim `exp` may
  only shorten it. A grant does not become long-lived because an IdP hook says so.
- **`acr` is checked in the issued token**, not assumed from what was requested — an IdP may
  decline a step-up and issue anyway.
- **Embedded mode refuses every grant**: single-use needs the shared store that only the
  distributed mode has.
- **An invalid grant refuses the whole token** — a 401 naming the grant, not a quiet
  downgrade to the unelevated principal that would surface later as a confusing 403.
- **A grant on a tenant-plane issuer is ignored** (no cap to lift), and it cannot rescue a
  subject whose groups map to no role — it lifts a ceiling, it is not a route to authority.
- **Audit:** every record produced under a grant carries `grant=<id>`. Unelevated records are
  unchanged and carry no such field.

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
