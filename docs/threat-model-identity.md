# Threat Model Addendum — Federated Identity (IdP → BFF → Gateway)

Companion to [threat-model.md](threat-model.md). [ADR-0007](adr/0007-federated-identity-oidc-and-gateway-rbac.md)
introduces OIDC-federated identity with break-glass static keys and makes the gateway the
single source of authorization. That change **moves and adds trust boundaries** the base
threat model does not cover, and §7 of that model names "the auth model changes (JWT/OIDC)"
as a trigger to revisit. This addendum is that revisit.

It is **gating**: ADR-0007 marks it *required before implementation*. The controls below are
therefore stated as **requirements to build** (`TM-I-nn`, status **[planned]**), not as
controls already shipped. They become the acceptance criteria for the auth-core work. When a
requirement lands it should be re-tagged with its implementation finding ID, exactly as the
base model rows carry `F-nn`.

Companion docs: [rbac-roles.md](rbac-roles.md) (the scope/role matrix this protects),
[security-mtls.md](security-mtls.md) (the authenticated-channel option for I4),
[audit-logging.md](audit-logging.md) (where the real-user `subject` must land).

## 1. New / changed assets

In addition to the assets in the base model, the identity path introduces:

| Asset | Why it matters |
|-------|----------------|
| **IdP trust configuration** (`issuer`, `audience`, allowed algs, `group_roles` map) | The root of all inbound trust — a wrong/loose value (e.g. unpinned issuer, `alg:none`, wildcard audience) silently accepts forged identity |
| **Cached JWKS (IdP signing keys)** | The gateway validates every JWT against this; a poisoned or stale cache means forged or replayed tokens validate |
| **User access / ID tokens** | Bearer credentials for a *human*; if leaked they impersonate that user with their scopes until expiry |
| **BFF session + its signing secret** | The browser-facing credential; controls who the BFF believes the user is, and (today) protects the opaque session cookie |
| **BFF→gateway assertion key / mTLS client identity** | The new highest-value secret: whoever holds it can mint identity for *any* user to the gateway (see I4) |
| **OAuth ephemeral secrets** (PKCE verifier, `state`, `nonce`) | Bind the callback to the request; loss enables code interception / CSRF login |

## 2. New trust boundaries

The base model's primary authn boundary was **B1 (Client → Gateway)**, fed by a static key.
Federated identity inserts a chain *in front of and beside* B1:

```
            (I1)             (I2)                         (I4)
 User-agent ───► BFF ────────► IdP (authorize + token)    BFF ───► Gateway ──► … (B2–B4 unchanged)
 (untrusted)   (RP / now      (external, semi-trusted)    │      (authz point)
                identity-                                  │ per-user identity assertion
                relay)                                     │ (token passthrough OR signed BFF assertion)
                                                           ▼
                                              (I3) Gateway ───► IdP JWKS (signing keys)
```

- **I1 — User-agent → BFF.** The OIDC Relying-Party boundary. The browser is untrusted; the
  BFF runs the Authorization-Code + PKCE flow and holds tokens server-side. CSRF on the
  callback and session integrity live here.
- **I2 — BFF → IdP.** Outbound to an external, *semi-trusted* IdP (authorize redirect + token
  exchange). The IdP is authoritative for identity but is off-platform and can be
  mis/over-configured.
- **I3 — Gateway → IdP JWKS.** A **new outbound dependency** from the gateway to fetch signing
  keys. It is an availability and integrity dependency (and an SSRF-shaped surface — the
  issuer URL is config, not user input, but must still be policy-checked).
- **I4 — BFF → Gateway (identity assertion).** The base model's B1, *transformed*. The BFF
  stops being a single-admin-key proxy and instead asserts the **end user's** identity, either
  by **passing through the user's OIDC token** or by minting a **signed BFF assertion**. This
  is the single highest-value new attack surface: a forgery here is full impersonation.

B2 (Gateway→Redis), B3 (Redis→Worker), B4 (Worker→Device) are **unchanged** — except that the
`subject` now flowing through them is a real user, which *raises* the value of the existing
F-30 subject-propagation control.

## 3. New / changed adversaries

In addition to the base model's adversaries:

6. **Token forger** — crafts or alters a JWT (algorithm confusion, `alg:none`, `kid`
   injection, signature stripping, claim tampering to add scopes/groups) to spoof identity or
   elevate.
7. **Network attacker on I3/I4** — sits between gateway and JWKS, or between BFF and gateway,
   to poison keys, strip the assertion, downgrade the channel, or replay tokens.
8. **Compromised / malicious BFF** — the BFF now holds user tokens *and* the assertion key.
   A compromised BFF can impersonate any user. (Previously it could only act as the one admin
   key — the blast radius grows, and must be bounded.)
9. **Phishing / login-CSRF attacker** — forces or intercepts the OAuth callback (missing
   `state`/`nonce`, open redirect, code interception) to log a victim into an attacker context
   or vice-versa.
10. **Misconfigured / partially-compromised IdP** — over-broad audience, attacker controls a
    group the `group_roles` map elevates, or IdP signing-key compromise.

Still out of scope (unchanged): full host/root compromise of a node; an operator holding
`MCP_SECRET_KEY` / break-glass admin key (that key *is* an authority by design); cross-tenant
attacks within one stack (D-1).

## 4. STRIDE by new boundary

Each row maps to a `TM-I-nn` requirement (control to build) or an explicitly accepted risk —
a row with neither is a gap, same rule as the base model.

### I1 — User-agent → BFF (OIDC Relying Party)

| STRIDE | Threat | Control (requirement) |
|--------|--------|------------------------|
| **S**poofing | Login-CSRF / fixation — attacker completes a flow into the victim's session | **TM-I-01 [planned]:** unguessable, single-use, session-bound `state` **and** `nonce`; reject callback on mismatch; rotate session ID on login (ADR-0007 §Decision 4 callback CSRF/state) |
| **T**ampering | Forged/altered session cookie elevates role at the BFF | **TM-I-02 [planned]:** keep the existing signed, opaque, `HttpOnly`/`Secure`/`SameSite` session; the BFF's role view is **advisory only** — the gateway re-authorizes every call on scopes (no BFF-side authz is load-bearing) |
| **R**epudiation | "I didn't log in / didn't do that" | **TM-I-03 [planned]:** record login + the resolved `subject` to the audit trail; downstream actions already attributed at the gateway (F-55/F-56) |
| **I**nformation disclosure | Tokens leak to the browser / JS / logs | **TM-I-04 [planned]:** tokens stay **server-side** in the BFF session store; never in `localStorage`, URL, or response body; redact in logs (consistent with F-59) |
| **D**enial of service | Callback / token-exchange flood | Reuse the existing edge rate limits (F-16) at the BFF login routes — **accepted via existing control** |
| **E**levation | Victim driven through attacker's auth code (code injection) | Covered by **TM-I-01** (PKCE binds the code to *this* client+verifier; `state` binds to *this* session) |

### I2 — BFF → IdP

| STRIDE | Threat | Control (requirement) |
|--------|--------|------------------------|
| **S**poofing (of the IdP) | BFF talks to an impostor authorize/token endpoint | **TM-I-05 [planned]:** discovery + endpoints over TLS with standard cert validation; `issuer` pinned in config; no plaintext HTTP |
| **T**ampering | Authorization-code interception / replay | **TM-I-06 [planned]:** Authorization Code **+ PKCE (S256)** mandatory; one-time code exchange server-side |
| **I**nformation disclosure | `client_secret` / tokens exposed | **TM-I-07 [planned]:** confidential-client secret injected via env (never ConfigMap, per existing secret hygiene); token endpoint called server-to-server only |
| **R**epudiation | — | IdP-side; out of scope (the IdP is authoritative) |

### I3 — Gateway → IdP JWKS (and JWT validation)

This is where most forgery is stopped. Treat it as the core of the addendum.

| STRIDE | Threat | Control (requirement) |
|--------|--------|------------------------|
| **S**poofing | Forged JWT accepted | **TM-I-08 [planned]:** validate signature against JWKS; enforce `iss`, `aud`, `exp`/`nbf` (with bounded clock skew); **algorithm allow-list (asymmetric only)** — reject `alg:none` and HS/RS confusion; match `kid` to a known key, never trust an embedded key |
| **T**ampering (JWKS poisoning) | Attacker swaps/forces a signing key | **TM-I-09 [planned]:** fetch JWKS only from the pinned issuer over TLS; cache with a **bounded TTL + negative-cache**; on `kid` miss, refresh **rate-limited** (no unbounded refetch-on-demand → no DoS amplification); never accept keys from the token itself |
| **I**nformation disclosure (SSRF) | A crafted issuer/JWKS URL reaches internal services | **TM-I-10 [planned]:** issuer/JWKS URLs are **operator config, not request input**; still run them through the existing egress URL policy (block private/loopback/link-local, scheme allow-list) at startup (reuse F-02) |
| **R**eplay | Captured token reused before expiry | **TM-I-11 [planned]:** short token lifetime is the primary control; bind to `aud=gateway`; **optionally** track `jti` for the configured skew window. Document residual replay-within-TTL as accepted |
| **D**enial of service | JWKS endpoint slow/down blocks all auth | **TM-I-12 [planned]:** serve from cache through an IdP outage; **break-glass static keys (ADR-0007 §Decision 2) remain valid** so operators are never locked out; fail **closed** for OIDC, **open to keys** — i.e. no key, IdP down ⇒ 401, not bypass |
| **E**levation | Tampered `groups`/`roles` claim grants extra scopes | Signature validation (**TM-I-08**) makes claims tamper-evident; `group_roles` mapping is **gateway-side** config (ADR-0007 §Decision 3) so the IdP can only assert *membership*, never scopes directly |

### I4 — BFF → Gateway (per-user identity assertion) — highest value

Two modes from ADR-0007 §Decision 4; the threats differ.

**Mode A — token passthrough** (BFF forwards the user's OIDC token; gateway is an audience):

| STRIDE | Threat | Control (requirement) |
|--------|--------|------------------------|
| **S**poofing | Forged/foreign token presented | Validated exactly as I3 (**TM-I-08**); gateway must be in `aud` — a token minted for another audience is rejected |
| **I**nformation disclosure | Token sniffed on the BFF→gateway leg | **TM-I-13 [planned]:** that leg is TLS (reuse `rediss`/mTLS posture, [security-mtls.md](security-mtls.md)); token is `Bearer`, never logged |
| **E**levation | BFF widens the user's scopes | Impossible by construction — the gateway derives scopes from the **validated token's** groups, not from anything the BFF says |

**Mode B — signed BFF assertion** (BFF mints a short-lived user-context JWT / signed header when passthrough isn't possible):

| STRIDE | Threat | Control (requirement) |
|--------|--------|------------------------|
| **S**poofing (assertion forgery) | Attacker mints a "user X / admin" assertion | **TM-I-14 [planned]:** assertions are signed with a **dedicated BFF key the gateway pins**, short TTL, `aud=gateway`, carry `sub`+groups+a request-bound `jti`; gateway accepts assertions **only** over an authenticated channel (mTLS or shared key) and **only** from the BFF identity — the BFF→gateway trust is explicit and narrow |
| **T**ampering | Assertion altered in flight | Signature + authenticated channel (**TM-I-14**); reject on any validation failure, audited |
| **R**epudiation | Disowning a minted assertion | **TM-I-15 [planned]:** the BFF logs every assertion it mints (`sub`, `jti`, scopes-requested); gateway logs every one it accepts → both ends reconcilable |
| **E**levation of privilege | **Confused-deputy / over-trust:** the gateway treats the BFF as fully trusted and lets it assert *any* identity | **TM-I-16 [planned]:** the assertion is **identity-only** — it carries `sub`+groups, and the gateway **re-derives scopes itself** via `group_roles`; the BFF can never assert scopes. Bound the BFF's blast radius: its assertion key is *not* an admin key, and a compromised BFF is contained to "can impersonate logged-in users," not "is gateway admin" |
| **D**enial of service | Stolen assertion key | Short TTL limits the window; **TM-I-17 [planned]:** key is independently rotatable (separate from device-credential Fernet keys and the break-glass admin key) |

> **Decision needed at implementation:** prefer **Mode A (passthrough)** wherever the IdP can
> issue a gateway-audience token — it has strictly fewer secrets and no BFF-minting surface.
> Mode B is the fallback for raw-LDAP / audience-constrained IdPs and **must** ship with
> TM-I-14…17 or not at all.

## 5. Accepted risks & residuals (identity)

| Risk | Disposition |
|------|-------------|
| **Token replay within its TTL** | **Accepted** — mitigated by short lifetimes + `aud` binding; `jti` tracking optional (TM-I-11). Full anti-replay would need server-side token state |
| **Break-glass admin key is a standing high-value credential** | **Accepted by design (ADR-0007)** — the cost of removing the IdP-down lockout risk; mitigated by env-only injection, rotation, and audit. At least one such key must exist |
| **A compromised BFF can impersonate currently-authenticatable users** | **Bounded, not eliminated** — TM-I-16 contains it to *user* impersonation (not admin), identity-only assertions, short TTL, rotatable key. Residual is inherent to any reverse-proxy SSO |
| **IdP compromise / a maliciously-administered IdP group** | **Out of scope** — the IdP is the authority for identity; `group_roles` limits damage to mapped roles, but a fully hostile IdP is a trust-root failure |
| **Interim BFF-centric phase** (if shipped before token relay) leaves audit showing the BFF | **Tracked** — explicitly an interim per ADR-0007 *Alternatives*; not the end state, and must be time-boxed |

## 6. Pre-implementation checklist (the gate)

Auth-core implementation is cleared to start when these are designed and have owners. Treat
each as a definition-of-done item:

- [ ] **TM-I-08/09** JWT + JWKS validation: alg allow-list, `iss`/`aud`/`exp`, bounded-TTL
      cache with rate-limited `kid`-miss refresh, no token-embedded keys.
- [ ] **TM-I-12** fail-closed-for-OIDC / open-to-break-glass behavior on IdP outage, with an
      explicit test (IdP down ⇒ key works, no key ⇒ 401).
- [ ] **TM-I-01/06** PKCE + `state` + `nonce` on the BFF login/callback; server-side tokens.
- [ ] **I4 mode chosen** (A preferred); if **B**, TM-I-14…17 (pinned key, authenticated
      channel, identity-only assertion, rotation) are in the design.
- [ ] **TM-I-16** confirmed: BFF asserts identity only; gateway re-derives scopes. No
      BFF-side authz is load-bearing.
- [ ] Audit shows the **real user** `subject` end-to-end (extends F-30); login + assertion
      mint/accept both logged.

## 7. Maintenance

Revisit this addendum when: the I4 mode changes (passthrough ↔ assertion), a raw-LDAP adapter
is added (a new identity ingress), token-exchange/OBO (RFC 8693) is introduced, the
`group_roles`/scope model gains a tenant dimension (ADR-0004 resumes), or the IdP integration
moves from JWT validation to introspection. Fold accepted-and-then-implemented `TM-I-nn`
rows back into [threat-model.md](threat-model.md) with their finding IDs once they ship, so
the base model stays the single STRIDE reference.
