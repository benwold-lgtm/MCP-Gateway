# Connecting an identity provider

How a person's rights get from your IdP into this gateway, what the gateway needs your IdP to
provide, and how to configure specific vendors.

> **What has been tested, and what has not.**
>
> **Keycloak** and **Authentik** are both verified end to end against running instances —
> real authorization-code flows, real tokens, real JWKS fetched over a network. The
> walkthroughs for those two are written from working configuration.
>
> **Entra ID, Okta and Google Workspace have not been tested against this gateway.** Their
> sections describe the integration path each one's documented behaviour implies, and name
> the specific thing to verify first. Treat them as a starting point that still needs
> proving, not as a supported configuration. If you integrate one, the
> [verification section](#verifying-an-integration) is how to find out whether it actually
> worked — several of the failure modes here are silent.

---

## How authorization flows

**The IdP never says "admin".** It says *"this person is in the group `mcp-operators`"*. A
mapping in **your gateway config** decides what that means. Keeping that decision on this side
is deliberate — ADR-0007 §Decision 3 — and it is why an IdP administrator cannot grant
themselves gateway authority by editing a directory.

```
IdP authenticates the user
      │
      │  issues an ACCESS TOKEN (a signed JWT):
      │    iss:    https://login.example.com/realms/corp
      │    aud:    device-mcp-gateway
      │    sub:    a4f1…
      │    groups: ["mcp-operators"]          ← the only authorization input
      ▼
Console BFF   holds the token in a SERVER-SIDE session
              (the browser gets an opaque cookie; it never sees the token)
      │
      │  relays the USER'S OWN token as the bearer on every call
      ▼
Gateway   1. resolve `iss` → select THAT issuer's config, and only its JWKS keys
          2. verify signature, `aud`, `exp`
          3. read the groups claim          → ["mcp-operators"]
          4. group_roles["mcp-operators"]   → "viewer"        ← your config, not the IdP
          5. scopes_for_role("viewer")      → {devices:read, metrics:read}
      │
      ▼
require_scope("devices:write") → 403.  /auth/me returns the scope set; the console
                                       greys out what the scopes do not cover.
```

Three consequences that catch people out:

- **The group name is the join key, and nothing validates that the two sides agree.** Rename a
  group in the IdP and its members silently lose access — a valid token whose groups map to
  nothing authenticates with an *empty scope set*, so every route answers 403 rather than 401.
  The audit records who was denied.
- **The mapping is per issuer, with no shared or fallback table.** Two trusted IdPs may both
  have a group called `mcp-admins`; they are unrelated. Without this rule, an administrator of
  one trusted IdP could create a group named after another issuer's mapping and inherit its
  scopes.
- **The audit subject is `oidc:{issuer}#{sub}`.** `sub` is unique within an issuer, not
  globally, which matters as soon as there is more than one.

### Where per-user identity stops

At the device. The chain above is per-user from the browser to the gateway; the call the
gateway then makes to an appliance uses **that device's own credential** — one service
account per device, the same one for every user of the tenant.

```
BSmith --token--> BFF --the same token--> Gateway --one device credential--> appliance
       \_____________ per-user identity ___________/       \_ one service identity _/
```

This is the accepted, permanent model, not a gap awaiting a fix
([ADR-0026](adr/0026-service-identity-per-device.md)). It is worth being concrete about what
it does and does not buy, because the expectation it disappoints is a reasonable one:

- **Worth doing anyway:** point the appliance's *own* console at the same IdP. One identity,
  one lifecycle, one MFA and offboarding path for a person across both consoles.
- **Not achievable:** "the gateway creates this VM *as BSmith*". Human-at-a-console and
  machine-calling-an-API are different paths, and the second one is the gateway's.
- **How the question is actually answered:** the gateway's audit record names BSmith; the
  appliance's log names the service account; both carry the same `X-Request-Id`, which the
  gateway is required to send on every device call. Join on it — see
  [audit-logging.md](audit-logging.md#attribution-across-the-device-hop-adr-0026).

---

## What the gateway needs from your IdP

Any provider that satisfies this contract works. Everything vendor-specific below is just
*how* to make that vendor satisfy it.

| # | Requirement | Why |
|---|---|---|
| 1 | **The access token is a signed JWT** (RS256 or another asymmetric algorithm) | The gateway verifies the token it is handed. `HS*` and `none` are refused by an explicit allow-list |
| 2 | **A discoverable JWKS endpoint over https**, reachable *from the gateway* | Signature verification. Auto-discovered from the issuer; `jwks_uri` can be set explicitly for air-gapped deployments. A plaintext `http://` issuer is refused **at startup** unless explicitly allowed |
| 3 | **`aud` matches a value you configure** | Present and checked. Several IdPs do **not** set a useful `aud` by default — see the traps |
| 4 | **A claim carrying group (or role) membership, in the ACCESS token** | The authorization input. The claim *name* is configurable (`groups_claim`); its **values** are what your `group_roles` table keys on |
| 5 | **A stable `iss`** that is byte-identical to what you configure | The issuer is compared exactly and is also where JWKS is fetched from |

Requirement 4 is where vendors differ most, and it is worth being precise about: the claim
must be in the **access token**, not only the ID token. Some IdPs make this easy, some need a
specific mapper, and at least one cannot do it at all.

### The configuration shape

```yaml
gateway:
  oidc:
    enabled: true
    issuers:
      - issuer: "https://login.example.com/realms/corp"   # byte-for-byte, incl. any trailing /
        audience: "device-mcp-gateway"                    # must equal the token's `aud`
        groups_claim: "groups"                            # rename per vendor (see below)
        subject_claim: "sub"
        algorithms: ["RS256"]
        group_roles:                                      # THIS is your authorization policy
          mcp-admins:    admin
          mcp-operators: viewer
```

A user in several mapped groups receives the **union** of the mapped scopes. Roles and their
scope bundles are documented in [rbac-roles.md](rbac-roles.md).

---

## Keycloak

*Verified against Keycloak 26.x.*

1. **Create a realm** for the population that will sign in, and a **client** for the console
   (standard flow / authorization code; public or confidential both work).
2. **Create groups** whose names you will map — e.g. `mcp-admins`, `mcp-operators` — and add
   users to them.
3. **Add a group-membership mapper** on the client, and set two things that are not the
   defaults:

   | Mapper setting | Value | Why |
   |---|---|---|
   | Mapper type | `Group Membership` | |
   | Token Claim Name | `groups` | Must match `groups_claim` |
   | **Full group path** | **`OFF`** | ⚠️ **On (the default) emits `/mcp-admins` with a leading slash.** Your `group_roles` keys on `mcp-admins`, the two never match, and every user gets an empty scope set |
   | **Add to access token** | **`ON`** | The gateway reads the access token, not the ID token |

4. **Add an audience mapper.** ⚠️ **Keycloak's `aud` defaults to `account`**, which will not
   match your configured audience — the token then fails validation for a reason that looks
   nothing like the cause. Add an `Audience` mapper with *Included Client Audience* set to your
   gateway's audience value, and *Add to access token* ON.
5. **Pin the hostname.** Set `KC_HOSTNAME`. Without it, `iss` follows the incoming `Host`
   header, so a browser and an in-cluster JWKS fetch can see two different issuer strings for
   the same realm — and the gateway compares `iss` exactly.

```yaml
      - issuer: "https://login.example.com/realms/corp"
        audience: "device-mcp-gateway"
        groups_claim: "groups"
        group_roles:
          mcp-admins:    admin
          mcp-operators: viewer
```

---

## Authentik

*Verified against Authentik 2025.8.*

1. Create an **OAuth2/OpenID Provider** and an **Application** in front of it. Note the
   application **slug** — it appears in the issuer URL.
2. Set **Client type** (public is fine for a browser console), and choose a **signing key** so
   the provider issues RS256 JWTs.
3. Set **Subject mode** to whatever you want as the audit subject (`user_username` gives
   readable audit rows; the default UUID is equally valid and more stable across renames).
4. Set **Issuer mode**:
   - `per_provider` → `https://auth.example.com/application/o/<slug>/`
   - `global` → `https://auth.example.com/`

   Either works. Configure whichever you chose, **exactly**.
5. **Create groups** (`mcp-admins`, `mcp-operators`) and add users. Authentik emits group names
   in the `groups` claim and sets `aud` from the client ID automatically — so unlike Keycloak,
   no audience mapper is needed.

⚠️ **The trailing slash is part of the issuer.** With `per_provider`, the issuer ends in `/`
and it is compared byte-for-byte. Strip it and every login returns 401 — correctly, but the
message will not point you here.

⚠️ **Authentik derives `iss` from the request `Host` header** and has no server-side pin
equivalent to `KC_HOSTNAME`. Fetching discovery through a different hostname yields a
different issuer string. Keep every client on one hostname.

```yaml
      - issuer: "https://auth.example.com/application/o/mcp-gateway/"   # note the slash
        audience: "mcp-gateway"          # = the Authentik client ID
        groups_claim: "groups"
        group_roles:
          mcp-admins:    admin
          mcp-operators: viewer
```

---

## Microsoft Entra ID

> ⚠️ **Not tested against this gateway.** The path below follows from Entra's documented
> behaviour and needs verifying before you rely on it.

**Use app roles, not groups.** Entra emits group membership as **object GUIDs**, not names, for
cloud-only groups. That technically works — you can key `group_roles` on GUIDs — but it makes
your authorization policy unreadable and unreviewable:

```yaml
        group_roles:
          "8f4c1e02-...-9b2a": admin        # which group is this? nobody knows
```

**App roles avoid the problem entirely.** Define app roles on the application registration with
value strings you choose (`mcp-admins`, `mcp-operators`), assign users or groups to them, and
point the gateway at the `roles` claim:

```yaml
        groups_claim: "roles"             # Entra emits app roles here
        group_roles:
          mcp-admins:    admin
          mcp-operators: viewer
```

**No gateway change is needed** — `groups_claim` is already a per-issuer setting, and the
gateway does not care whether the claim is called `groups` or `roles`.

Two things to check first:

- **The `aud` of an Entra access token is the resource/API it was issued for**, not your client
  ID. Configure `audience` to match the API's application ID URI, and make sure the console
  requests a token for that resource rather than a bare `openid` token — an ID token will not
  do.
- **The groups overage limit** (roughly 200 group memberships) replaces the claim with a link
  to Microsoft Graph. If you use the `groups` claim and a user exceeds it, the claim is
  *absent* — the user authenticates with an empty scope set and gets 403 everywhere. App roles
  are not subject to this, which is a second reason to prefer them.

---

## Okta

> ⚠️ **Not tested against this gateway.** The path below follows from Okta's documented
> behaviour and needs verifying before you rely on it.

The gateway needs a groups claim **in the access token**. On Okta this generally requires a
**custom authorization server** (API Access Management) — the default org authorization server
does not let you add custom claims to access tokens. Note that this is a licensed feature on
some Okta tiers; confirm your plan includes it before designing around it.

1. Create a custom authorization server, and note its **audience** value.
2. Add a **groups claim** to it: token type **Access**, value type **Groups**, with a filter
   matching the groups you want to emit (e.g. starts with `mcp-`). Filter deliberately — an
   unfiltered claim ships every group a user is in.
3. Point the gateway at that authorization server's issuer.

```yaml
      - issuer: "https://example.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9"
        audience: "api://device-mcp-gateway"      # the custom auth server's audience
        groups_claim: "groups"
        group_roles:
          mcp-admins:    admin
          mcp-operators: viewer
```

**No gateway change expected** — this should be configuration only. The thing to verify first
is that the groups claim actually lands in the **access** token and not just the ID token.

---

## Google Workspace

> ⚠️ **Not tested — and unlike the two above, this one is not expected to work as-is.**

**Google's OIDC tokens do not carry group membership.** There is no mapper, scope, or setting
that adds it: group membership lives in the Admin SDK Directory API and is not expressed as a
token claim. Requirement 4 of the contract cannot be met.

This is a genuine gap, not a configuration difficulty. Three ways round it, in the order we
would consider them:

1. **Front Google with an IdP that can do it.** Keycloak, Authentik, Okta and Entra can all
   federate Google as an upstream identity source while issuing their own tokens with their own
   group claims. This needs **no change to this gateway**, and is the recommended route today.
2. **Resolve groups from the Directory API at login.** This would be a real feature, not a
   config option: an outbound authenticated call per login (service account with domain-wide
   delegation), plus caching, plus a decision about what happens when the directory is
   unreachable — fail closed and lock everyone out, or fail open and over-grant. It is the
   first thing that would justify a "resolve groups from a directory" abstraction in the
   gateway, which does not exist today.
3. **Map individual subjects rather than groups.** Not supported: `group_roles` keys on group
   claim values, and per-user mapping in gateway config would put a user directory in a
   config file, which is the thing this design deliberately avoids.

If you need Google Workspace, option 1 is the answer today. Option 2 is the one to discuss if
that is not acceptable — it is scoped work, not a setting.

---

## Silent failure modes

These are the ones worth knowing in advance, because each produces a symptom that points
somewhere other than the cause.

| Symptom | Actual cause |
|---|---|
| Every SSO user gets **401**, while API-key holders keep working normally | The gateway cannot reach the IdP's JWKS endpoint, so OIDC validation fails and the gateway falls through to its **static break-glass keys**, which keep working. **It reads like an IdP fault.** Check egress first: the shipped NetworkPolicy allows only **80/443/8080/8443** outbound — an IdP on any other port is unreachable. The same rule also `except`s the pod and service CIDRs and loopback, so an **in-cluster** IdP is blocked too |
| The gateway cannot reach an on-premises IdP on a private address | `security.allow_private_targets: false` (the default) blocks it. ⚠️ The name and its config comment both talk about *device* targets, but the same switch gates **IdP and JWKS fetches** — set it to `true` for an on-prem IdP. The error message names the setting |
| The gateway **refuses to start**, naming the issuer | The issuer (or `jwks_uri`) is `http://`. Refused by default: the IdP's signing keys and every access token would cross the network in the clear. Use https, or set `security.allow_plaintext_idp: true` for a lab — it is warned about loudly at startup. There is no localhost exemption |
| Users authenticate but get **403 on everything** | The groups claim is absent, empty, or its values do not match any `group_roles` key. Most often: Keycloak's full-path slash, a claim that is in the ID token but not the access token, or Entra GUIDs vs names |
| The IdP is refused at startup or on refresh, and **nothing is cached**, even though the issuer looks right | The discovery document at `<issuer>/.well-known/openid-configuration` declares a *different* `issuer` than the one you configured. Refused deliberately: pinning `iss` at decode time does not cover this, because whoever supplies the **keys** also chooses the claims. Common with a reverse proxy that rewrites the hostname |
| A token that *should* work is refused with an issuer or key error | `iss` mismatch — a trailing slash, or a hostname that differs between the browser and the gateway |
| A config change to the IdP has no effect for up to ten minutes | JWKS is cached for `jwks_cache_ttl` (default 600s, 30s floor on a key-id miss). Lower it or restart the gateway pods while iterating |
| Startup warns that your `oidc` block is an unknown key | An older build. The key **is** honoured; do not delete your working auth config on the strength of that warning |

---

## Verifying an integration

Configuring an IdP and *proving* it works are different things, and several failure modes
above are silent — a login that succeeds is not evidence that authorization is correct.

Check these in order. Each one fails differently, which is the point.

1. **The gateway can fetch JWKS.** From inside the gateway's own network context, not from
   your laptop:
   `curl -s <issuer>/.well-known/openid-configuration | jq -r .jwks_uri` then fetch it. A
   200 here rules out the egress and NetworkPolicy traps in one step.
2. **Decode a real access token** — not the ID token — for a test user, and confirm by
   inspection: `iss` byte-identical to your config, `aud` matching, and the groups claim
   present **with the values you expect** (unslashed names, not GUIDs, not paths).
3. **A mapped user gets the right scopes.** Call `/auth/me` with that token. Getting an empty
   scope list here means the claim did not match the table, and is the most common outcome of
   a first attempt.
4. **An unmapped user gets nothing.** Sign in as a user in *no* mapped group and confirm an
   empty scope set and a 403 — not an error, not a default role. This is the check that proves
   the mapping discriminates rather than everyone landing on the same role, and it is worth
   more than the positive case.
5. **A privileged action is actually refused.** Have the low-privilege user attempt something
   their role does not cover and confirm a 403 from the *gateway*. A console that greys out a
   button proves only that the console read `/auth/me`.

Step 4 is the one people skip. A first integration where every user happens to be an admin
looks identical to a working one.
