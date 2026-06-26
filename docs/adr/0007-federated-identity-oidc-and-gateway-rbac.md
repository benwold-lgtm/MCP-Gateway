# ADR-0007: Federated identity (OIDC) with break-glass local keys; the gateway owns RBAC

- **Status:** Proposed
- **Date:** 2026-06-26
- **Related findings:** F-15 (inbound RBAC), F-30 (end-to-end identity propagation)
- **Builds on:** [ADR-0006](0006-fail-closed-distributed-defaults.md) (fail-closed auth gates); intersects [ADR-0004](0004-single-tenant-per-stack.md) (tenancy)

## Context

The gateway already has real, scope-based RBAC ([rbac.py](../../device_mcp_gateway/rbac.py)):
a request resolves to a `Principal{subject, scopes}`, routes authorize on individual
**scopes** (`devices:read`, `devices:write`, `tools:call`, `metrics:read`), and roles are
just named bundles of scopes. The `Authenticator`/`authenticate_request` seam was
deliberately shaped so that "swapping to JWT/OIDC later changes only the authenticator —
every route's `require_scope(...)` and the audit `subject` stay put." Today that seam is fed
only by **static API keys** (key → role → scopes).

The management **UI/BFF** grew a *separate* identity model: a shared password → role, with
role enforced only at the BFF, and the BFF holding **one gateway admin key that it uses for
every upstream call**. The result is three problems:

1. **Two disjoint role systems** — the UI's `admin`/`viewer` strings and the gateway's
   scopes are unrelated; they can (and did) drift.
2. **Audit attribution is lost** — every UI-initiated action is recorded against the BFF's
   key as `subject`, never the human who did it.
3. **No enterprise SSO** — operators run on-prem Active Directory or a cloud IdP and expect
   single sign-on; static keys don't federate.

Constraints that shape the solution: enterprises are split between **on-prem AD** and
**third-party cloud IdPs**, so a vendor-specific integration is the wrong bet. And smaller /
test / air-gapped deployments — and the initial install of *any* deployment — need a
**local admin and read-only account that works without an IdP**, which is also a security
best practice (an SSO outage must not lock operators out of their own gateway).

## Decision

We make the gateway the **single source of truth for authorization**, fed by **federated
OIDC identity** with **static keys retained as break-glass**, all through the existing
scope seam.

1. **Identity over OIDC, vendor-neutral.** Authentication is OAuth2/OIDC
   (Authorization Code + PKCE at the BFF; **JWT validation via JWKS** at the gateway's
   `authenticate()` seam). This single protocol covers the ~90%: **on-prem AD** via ADFS or
   Keycloak (LDAP/AD federation), and **cloud** via Entra ID / Okta / Auth0 / Google. We
   write to the standard — no per-vendor SDKs. Raw LDAP bind is explicitly **out of scope
   now** (the long tail); the authenticator stays pluggable so a direct-LDAP adapter can be
   added behind the same seam later, or covered by Keycloak federation.

2. **Composite authenticator with break-glass.** The gateway accepts **both**, evaluated per
   request: a valid OIDC JWT (issuer/audience/expiry/signature checked against cached JWKS) →
   claims mapped to scopes; **else** a configured static key (key → role → scopes); **else**
   `401`. The local `MCP_ADMIN_KEY` / `MCP_VIEWER_KEY` therefore remain available for
   bootstrap, CI/test, air-gapped runs, and **break-glass when the IdP/JWKS is unreachable**.
   This composes with [ADR-0006](0006-fail-closed-distributed-defaults.md): distributed mode
   still refuses to boot with *no* auth at all.

3. **The gateway owns role → scope, mapped from IdP groups.** The IdP asserts *group
   membership* (a `groups`/`roles` claim); a **`group → scopes` mapping in gateway config**
   is the one place roles are defined. The UI/BFF authorize on the **same scopes** (exposed
   via `/auth/me`), so UI and gateway permissions cannot diverge. Roles are still just scope
   bundles ([docs/rbac-roles.md](../rbac-roles.md) is the living matrix).

4. **End-to-end per-user identity (F-30).** The principal of a UI-initiated call is the
   **end user**, not the BFF. Preferred: **token passthrough** — the BFF forwards the user's
   access token and the gateway is a configured audience. Fallback where passthrough is not
   possible (e.g. raw-LDAP login, audience constraints): a **signed BFF identity assertion**
   (a short-lived BFF-minted JWT / signed user-context header) over an authenticated channel
   (mTLS or shared key) that the gateway trusts — consistent with the existing
   gateway → worker `subject` propagation (F-30). Either way, audit `subject` becomes the
   real user.

## Consequences

- **Positive:** enterprise SSO without vendor lock-in; a **single source of truth** for
  authorization (the gateway); **real per-user audit**; break-glass/local access preserved;
  **route code is unchanged** — `require_scope(...)` and the `Principal` contract stay put,
  exactly as the seam was designed for.
- **Negative / cost:**
  - The gateway gains a **JWT-validation dependency and failure mode** (JWKS fetch/cache/
    rotation, clock-skew tolerance, `iss`/`aud` config). Mitigated by a JWKS cache and by
    break-glass keys when the IdP is down.
  - The BFF gains an OIDC flow (callback CSRF/state, PKCE, server-side token handling) and
    must stop being a single-principal proxy.
  - A **new trust boundary** appears: BFF → gateway *identity assertion*. It must run over an
    authenticated channel and is the highest-value new attack surface — it needs its own
    threat-model treatment.
- **Follow-ups (deferred):**
  - **Threat-model addendum** for the IdP → BFF → gateway path (token validation, JWKS
    rotation/poisoning, assertion forgery, the BFF→gateway boundary). *Required before
    implementation.*
  - **Finer scopes** (split `devices:write` → create/update/delete; add `deadletter:manage`,
    `audit:read`) — additive, no route churn.
  - **Tenant-scoped roles** (e.g. `operator@tenant-a`) — the natural extension if the paused
    multi-tenancy work ([ADR-0004](0004-single-tenant-per-stack.md)) resumes; the claim→scope
    mapping is designed to carry a tenant dimension even while unused.
  - **Raw-LDAP adapter** for the long tail.
  - **Token-exchange (RFC 8693 / OBO)** if audience constraints make passthrough impractical.

## Alternatives considered

- **BFF-centric only** (IdP login at the BFF; BFF keeps its single gateway key; roles mapped
  at the BFF): rejected as the *target* — it leaves two role systems and audit still shows
  the BFF. Acceptable only as an interim phase, not the end state.
- **Raw LDAP bind first:** rejected as the primary path — no token to propagate to the
  gateway, it tends toward vendor specifics, and user passwords transit the BFF. Covered
  later via Keycloak federation or a pluggable adapter.
- **Per-vendor SDKs (Azure AD / Okta libraries):** rejected — lock-in; OIDC is the common
  denominator that serves all of them.
- **A gateway-local users/password database:** rejected — that reinvents an IdP. Static keys
  cover bootstrap/break-glass; OIDC covers everyone else.
- **Drop static keys once OIDC lands:** rejected — removes break-glass and the air-gapped/CI
  path, and creates a hard IdP dependency for booting. Keys stay, as a deliberate fallback.
