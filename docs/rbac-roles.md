# RBAC — scopes, roles, and IdP mapping

The gateway authorizes on **scopes**, not role strings. Roles are named **bundles of
scopes** ([rbac.py](../device_mcp_gateway/rbac.py) `ROLE_SCOPES`); routes only ever call
`require_scope(...)`, so adding a role never touches a route. This is the living reference
for the role/scope model; the *decision* behind it is
[ADR-0007](adr/0007-federated-identity-oidc-and-gateway-rbac.md).

## Scopes (the atoms)

| Scope | Grants | Route guards (examples) |
|-------|--------|--------------------------|
| `devices:read` | See devices and their state; **propose** a device-write plan (ADR-0022) — writes nothing, reaches nothing (see below); also the `require_scope` guard on **apply** (the actual gate there is the `devices:write-planned` grant below, checked inline) | `GET /v1/devices`, `GET /v1/devices/{h}`, `…/diagnostics`, `…/tools`, `…/tools/diff`, `…/deadletter` (inspect), `GET /v1/admin/overview`, `POST /v1/devices/plans`, `POST /v1/devices/plans/apply` |
| `devices:write` | Manage the fleet; **review and approve** a proposed device-write plan (ADR-0022) | `POST/PUT/DELETE /v1/devices/{h}`, `POST …/deadletter/replay`, `DELETE …/deadletter` (drain), `GET /v1/devices/plans/{id}`, `POST /v1/devices/plans/{id}/approve` |
| `tools:call` | Invoke a device's MCP tools | `GET /v1/devices/{h}/sse`, `POST /v1/devices/{h}/messages` |
| `metrics:read` | Read operational metrics | `GET /v1/metrics/summary` |
| `backup:read` | Export an archive of the registry; preview a restore (writes nothing) | `GET /v1/admin/backup`, `POST /v1/admin/backup`, `POST /v1/admin/restore/preview` |
| `backup:write` | Apply a restore | `POST /v1/admin/restore/apply` |
| `backup:export-portable` | **Additionally** export a *portable* archive — credentials re-encrypted to a passphrase instead of the stack key | `POST /v1/admin/backup` with `kind=portable` |
| `devices:write-planned` | Apply **exactly one** reviewed, digest-bound device-write plan (ADR-0022) | `POST /v1/devices/plans/apply` |

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

> **`devices:write-planned` never appears in any role's bundle, `admin` included, and never
> will by design.** Every other scope in this table is standing: hold the role, hold the
> scope, for as long as the credential is valid. This one is minted per-plan, at Review, by
> `write_planned.WritePlannedGrantStore.issue` — scoped to one caller and one exact plan
> digest — and redeemed once (or, if the reviewer explicitly marked it repeatable, on exact
> byte-identical reapplication only) via `write_planned.check_and_consume`, never via
> `require_scope`. `caller`'s baseline stays `devices:read` + `tools:call` permanently; an
> agent that needs to register or reconfigure a device proposes a plan, a human with
> `devices:write` reviews and approves it, and only *that* digest becomes appliable. See
> [ADR-0022](adr/0022-agent-initiated-device-writes-are-plan-bound.md).
>
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
| **console** (agent) | ✅ | ✅ | ✅ | ✅ | — | — | — | The console's BFF relaying a **password** session, which has no per-user token to pass through — **machine identity**. `operator` ∪ `caller`, and deliberately no `backup:*` (below) |

All seven roles are defined in [`ROLE_SCOPES`](../device_mcp_gateway/rbac.py) today
(`operator`/`auditor`/`caller` were added with the OIDC work, ADR-0007; `backup` with
ADR-0011; `console` with ADR-0023 slice 4). Add a role by adding one entry to `ROLE_SCOPES`
— no route changes. `devices:write-planned` has no column here, deliberately: it is not a
bundle member of any role, so the omission is not a gap to fill in later.

> **`console` exists because nothing else fitted, and that gap had a cost.** A password
> session reaches device CRUD and diagnostics, `/metrics/summary`, and the MCP invocation
> path — `operator` cannot invoke tools, `caller` cannot manage the fleet, so the console's
> BFF was given an **admin** key and with it every `backup:*` scope. The BFF compensates by
> refusing password sessions on all four backup/restore routes, in its own words because
> *"a password session proxies with the stack's admin token, which holds every `backup:*`
> scope, so admitting one here is a complete credential dump"*. That is a real guarantee
> enforced in the wrong layer: it holds only as long as no BFF route forgets the guard. A
> role that cannot express the scope moves it to the gateway, where a console-side bug
> cannot undo it.
>
> It is written in the source as the **union** `operator | caller` rather than a copied
> scope list, so that if `operator` gains a scope the console gains it too instead of
> quietly drifting behind.

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

#### More than one issuer

A deployment may trust more than one identity provider — two of the tenant's own IdPs, say,
during a migration. Use `issuers` instead of the single-issuer keys; setting both is refused at
startup:

```yaml
gateway:
  oidc:
    enabled: true
    issuers:
      - issuer: https://login.example.com/realms/corp
        audience: device-mcp-gateway
        group_roles:
          mcp-admins: admin
      - issuer: https://login.example.com/realms/contractors
        audience: device-mcp-gateway
        group_roles:
          mcp-operators: operator
```

Two rules, each of which exists because its absence fails **silently** — the token still
validates and the request still succeeds:

| Rule | Without it |
|---|---|
| The issuer is resolved from `iss` **first**, and the decode is pinned to that one issuer with only that issuer's keys | A token signed by issuer A's key while claiming `iss: B` is accepted — the holder of one IdP mints themselves an identity from another |
| `group_roles` is **per issuer**, with no shared or fallback mapping | An administrator of one trusted IdP creates a group named whatever another issuer's mapping keys on, adds themselves, and the gateway grants them that issuer's scopes |

> **Removed:** earlier releases described a second *provider* IdP, a per-issuer `plane` with a
> server-side scope ceiling, and elevated grants that lifted that ceiling for one request
> ([ADR-0013](adr/0013-two-plane-tenancy-and-the-provider-plane.md) §6/§6a/§11). That
> arrangement was replaced in design by
> [ADR-0017](adr/0017-provider-authority-is-delegated.md), where authority over a tenant is
> **delegated by that tenant** rather than asserted by the provider, and the implementation has
> been removed. `plane`, `step_up_acr`, `grant_claim` and `entitlement_claim` are no longer
> read; a config that still sets them is not broken, only ignored. No released version ever
> offered them.

## Future granularity

The scope set is the granularity lever; all of this is additive (no route churn):

- Split `devices:write` → `devices:create` / `devices:update` / `devices:delete`.
- Add `deadletter:manage` (separate DLQ recovery from general writes), `audit:read`.
- **Resource-/tenant-scoped** grants (e.g. `operator@tenant-a`) — the natural extension if
  multi-tenancy ([ADR-0004](adr/0004-single-tenant-per-stack.md)) resumes; the OIDC
  claim→scope mapping is designed to carry a tenant dimension even while unused.
