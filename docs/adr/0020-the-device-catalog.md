# ADR-0020: The provider's write path is a catalog; tenants claim from it

- **Status:** Accepted
- **Date:** 2026-08-17
- **Answers:** D2 (does the provider console offer device writes?), open since ADR-0013.
- **Prerequisite for:** [ADR-0017](0017-provider-authority-is-delegated.md) §1 — see §8.

## Context

"How does a provider add a device to a customer's fleet?" has never had an answer. The
provider console passes `canWrite={false}` unconditionally and always has; the tenant console
has a free-type registration form — hostname, base URL, auth, transport — that predates the
question being asked.

Both are unsatisfying for the same reason. Free-type registration asks a tenant administrator
to know an appliance's OpenAPI path, its auth shape and its transport, which is provider
knowledge. And the obvious fix — let the provider register devices directly into a tenant's
registry — requires precisely the cross-tenant write path that [ADR-0017](0017-provider-authority-is-delegated.md)
removes.

The product work reached "tenants claim from a curated catalog and never free-type" and filed
it as a deferred feature. It is not a feature. It is the shape that lets a provider do their
job with no standing authority inside a customer's stack, which makes it a prerequisite rather
than an enhancement.

## Decision

### 1. The catalog is a provider-plane object with no tenant reach

The provider curates **device types**: an appliance model, its OpenAPI document or MCP
endpoint shape, its transport, its expected auth kind, its fingerprint expectations, and the
scopes its tools should map to.

A device type is a **template, not an instance**. It names no host, holds no credential, and
belongs to no tenant. Curating one writes to provider-plane storage only — there is no code
path from catalog curation into any tenant's registry, which is what makes this compatible
with ADR-0017 rather than a way around it.

The catalog holds a **second kind of entry** — a service the provider actually operates and
offers to tenants, rather than a template for something the tenant owns. That is §6, and it
is the only place the provider supplies a host.

### 2. Assignment is an offer; claiming is the tenant's act

A provider **assigns** a device type to a tenant, which makes it appear in that tenant's
console as available. Assignment writes to the provider plane, not the tenant's registry.

The tenant **claims** it: supplies the host, supplies (or names) the credential, and the
device is registered in their own stack, by their own credential, in their own audit chain.

The division is the point. The provider says *what kind of thing this is*; the tenant says
*that it exists here, at this address, with this secret*. Neither can do the other's half, and
the boundary falls exactly where ADR-0017 puts it.

### 3. Claiming is the only registration path in a provider-operated estate

Free-type registration remains for **standalone and Lite deployments**, which have no provider
and therefore no catalog. In an estate, the tenant console offers claiming and not free entry.

This is a stronger statement than it looks and is worth defending: it means a tenant cannot
register an arbitrary endpoint in an estate deployment. That is deliberate. The catalog is
where a provider's operational knowledge lives — the fingerprint expectations of ADR-0015, the
egress policy a device needs, the auth shape that actually works — and an off-catalog device
has none of it. A tenant who needs something not in the catalog asks for it to be added, which
is a conversation the provider should be having anyway.

### 4. A device type is versioned, and a claimed device does not silently follow it

Updating a device type — a new OpenAPI document, a changed fingerprint expectation — produces
a **new version**. Claimed devices stay on the version they claimed until the tenant accepts
an upgrade.

Without this, a provider editing a catalog entry silently changes the behaviour of devices in
every customer's fleet at once: the single largest blast radius in this design, reachable by
a typo. The tool-set diff machinery that already exists is the right vehicle for showing a
tenant what an upgrade would change.

### 4a. A curated spec is embedded, not referenced (amendment, 2026-08-28)

> **Not built.** A device type version today carries `spec_path` and a declared `tool_set`
> and has no field for a curated spec document at all. This section decides what that field
> is before it is added, because the wrong answer is the easy one.

§1 says a device type "names no host". §4 says a claimed device stays pinned to the version
it claimed. Curating a spec the *provider* supplies — a normalised OpenAPI document for an
appliance whose own published one is wrong, incomplete or absent — appears to need a host,
and the naive answer is that the version stores a URL to fetch it from.

**Two different things are being called a host, and only one of them is what §1 prohibits.**

- A **dispatch-time host** is something a tenant's gateway calls at runtime to reach a live
  device. That is what §1 means, and §6 is the deliberate, heavily-obligated exception.
- A **curation-time source** is wherever the provider originally obtained the document,
  reached exactly once by the provider's own curation process and never again. It never
  becomes a tenant-facing dependency, and was never what §1 was protecting against.

#### Decision: the version holds the content, per version, immutably

A curated spec is **snapshotted into the version record**. It is not a live reference.

This is not merely the cleaner option; **§4 forecloses the alternative**. §4's guarantee is
that a claimed device stays on the exact version it claimed. If a version stored a URL, "the
version" would not be a stable artefact at all — it would change the moment whatever sits at
that URL changes, which is precisely the *"a provider's typo changes every customer's fleet
at once"* blast radius §4 exists to prevent, reintroduced one layer down through the spec
instead of through the type record. A live reference and a pinned version are mutually
exclusive, so the versioning requirement settles this rather than taste.

Concretely, at curation time the provider either pastes or uploads the document — no external
reach at all — or points curation at a source URL that is **fetched once** and snapshotted.
Prefer storing it **inline in the version row**: ADR-0025's restore story is point-in-time
recovery of one PostgreSQL database, and a document held anywhere else is a second store with
its own backup, its own restore ordering and its own way of being half-recovered. An
object-storage key internal to the provider plane stays available for documents large enough
to warrant it, and the cost of taking it is that second restore story, not a saved row.

Either way, **once curation completes the device type is self-contained**: neither claiming it
nor dispatching a tool against a claimed instance ever reaches back to where the document came
from.

#### Three spec mechanisms, deliberately different

They look alike — all three are "get a spec from somewhere" — and two of them already exist,
so the distinction is worth stating rather than leaving to be inferred:

| | Where it comes from | Freshness | Status |
|---|---|---|---|
| `spec_path` (§1) | joined to the **tenant's** `base_url` at claim time; the gateway fetches from the tenant's own device, cached for `registry.spec_cache_ttl` and refreshed | **must stay current** | built |
| `tool_set` (§1) | hand-entered by the curator; declared, never measured | n/a — an assertion | built |
| a curated spec document | the provider's own curation, snapshotted at version time | **must not drift** | this section |

`spec_path` is the reason this question had not come up: it is *relative*, so the host is
always the tenant's, and the existing live-fetch-with-TTL pattern carries no provider host
anywhere. That pattern is right for a device the tenant owns and wrong for a curated document,
and the two must not be collapsed because they superficially rhyme.

The consequence to accept openly: **a snapshot goes stale against whatever the vendor
publishes next, and that is the intended behaviour.** Re-curating produces a new version,
which reaches tenants as an offer through the upgrade path §4 already defines. There is no
mechanism by which a tenant's pinned device silently picks up a newer document, which is the
whole point.

#### The fetch still goes through the guard

If curation supports fetching from an operator-supplied URL, that fetch uses the existing
guarded-fetch discipline — `build_guarded_client` and the URL policy in
`security/url_policy.py` — even though the caller is a trusted provider curator rather than an
arbitrary agent.

Not because the threat model is the same; it plainly is not. For the same reason the plaintext
IdP flag was given no loopback exemption: one rule applied uniformly is easier to reason about
and to audit than a carve-out for "this caller is trusted enough to skip the guard", which is
the kind of exception that erodes.

### 4b. A snapshot is consumed by its own path (amendment, 2026-08-28)

> **Not built**, like §4a and for the same reason: none of this exists until a curated spec
> document does. Recorded now because each decision below has a cheaper wrong answer that is
> easiest to take mid-slice, under time pressure, with the ADR closed.

§4a decided what a curated spec *is*. Tracing it through the gateway showed it cannot yet be
consumed at all: [`DeviceConfig`](../../device_mcp_gateway/schemas.py) carries a `spec_url` and
nothing else, and `SpecService.fetch_spec` either GETs that URL or probes discovery paths on
`base_url`. There is no registration input that takes spec *content*. This section decides how
that gap is closed, because the cheap version of each answer is wrong in a way this codebase
has already been bitten by.

#### The claim path is a second construction path, not a new optional field

A device claimed from a catalog type is built by an **internal construction path that takes the
snapshot directly and never enters `spec_service.py`'s fetch logic**. Not the existing
`spec_url`-driven path with an optional `spec_content` bolted beside it.

One path that handles both *"fetch this live"* and *"this was already fetched, once, somewhere
else"* is a function with two preconditions and no way to tell which one it is under. That is
precisely the shape §7a found in the catalog's `auth.py` — a precondition stated accurately,
invalidated by a second caller, and nothing failing because the two cases were never
distinguished in code. Making them two paths means the ambiguity cannot arise.

#### `_check_target_url(spec_url, …)` does not apply, which is not the same as being skipped

On the claim path there is no URL to check, and the SSRF guard is therefore **inapplicable
rather than relaxed**. The distinction has to be stated or someone reading the diff will read
a missing guard as a weakening.

The guard's precondition is *a live fetch is about to happen*. For a claimed device that
precondition does not hold — nothing is fetched, at claim time or ever. The safety property it
enforces **was satisfied once already**, at curation time, by §4a's guarded fetch against the
provider's own source. That is a different invariant holding at a different moment, not the
same invariant loosened.

Collapsing "does not apply" into "was skipped" is the same category error this project has
already caught once. TM-I-05b found the egress policy allowing both `http` and `https` **by
design** — *"its job is SSRF, which is TM-I-10's control, not transport encryption"* — and the
fix was a second, independent control rather than an argument that the first one had been
weakened. Two properties, two moments, two controls.

#### `spec_hash` is recomputed at claim time and the catalog's stored hash is never trusted

The gateway hashes the snapshot's bytes itself, exactly as `fetch_spec` hashes what came back
over the wire.

This needs no fresh judgement — it is [ADR-0015](0015-endpoint-fingerprinting.md)'s own logic
with nothing adapted. ADR-0015 exists to *not accept an asserted identity*: pin it, then verify
against it. The hash stored on a catalog version is what curation **asserted**; recomputing
from the stored content at claim time is the verification, and here it is free — the bytes are
already in hand and no network fetch is involved.

What it buys is the case nothing else covers. If a bug, a migration or a compromised curation
path ever let a version's stored hash and stored content drift apart, trusting the stored hash
would never notice; recomputing catches it on the first claim against that version.

#### A version carries a curated document or a `spec_path`, never both

Enforced as a **write-time validation error**, by a `_check_curated_document` alongside
`_check_spec_path` in `repo.py` — same shape, same file, same "raise, don't reconcile".

Explicitly **not** "the curated document wins if both are set". A silent precedence rule is
what this project refuses everywhere else it has faced the choice: `devices:write-planned` is
deliberately not a member of any role bundle, so it can never be acquired by an implicit path;
an unnamed `break_glass: true` entry **refuses to start** rather than falling back to
`key:<role>`, because *"an omitted field must not silently produce the behaviour the ADR
forbids"*. A record that can hold both fields, resolved by a tie-break, is a state a future bug
reaches accidentally and which then fails silently instead of loudly. The ambiguity gets
resolved by the curator at write time or not at all.

#### `tool_set` becomes derived, because its stated premise expires

`VersionFields.tool_set` documents its own justification for being unverified: *"the catalog
has no tenant base_url to fetch a live spec against"*. That is true today and **stops being
true the moment a curated document sits in the row**.

This is worth naming plainly: §7a corrected this record for exactly this failure shape — a
written precondition that quietly became false — and leaving `tool_set` alone would reintroduce
an instance of it in the very next section. Left as a curator assertion, §4's upgrade diff
compares two unverified claims about what changed, when it could compare two tool sets parsed
from content already in hand. That is a strictly stronger guarantee, available for free, and
the only place in this whole change that **closes** an existing weakness rather than relocating
one.

So for a version carrying a curated document, the tool set is **derived from the snapshot** —
parsed at curation time, and re-derivable at claim time on the same reasoning as the hash —
rather than stored as a curator-supplied field. If curator-declared metadata about tools is
still wanted for some other purpose, it takes a **different field name**, so that nothing
downstream inherits the current docstring's expired premise by association with the old one.

`spec_path` versions keep the declared `tool_set` unchanged: there is no content in the row to
derive anything from, which is exactly what the docstring says.

#### Correction (2026-09-01): "one path" was wrong, and the fix is one choke point

> **Built 2026-09-01 — the choke point, not the whole path.** All five sites now ask
> `shared/spec_source.py::resolve_spec_source`, so a device carrying a snapshot is never
> fetched from at any of them, and LR-47's `pod_supervisor` bypass is closed on the way past.
> `DeviceConfig.curated_spec` carries the document and round-trips through Redis and SQLite.
>
> **What remains is the registration input.** Nothing can yet *set* that field: the gateway's
> register/update body has no `curated_spec`, and the BFF's claim path does not send one. So a
> curated document can be stored in the catalog and still cannot reach a device. The
> consumption machinery is in place and inert, which is the safe order — the sites were taught
> to respect a snapshot before anything could create one.

This section says a claimed device is built by "an internal construction path". Counted in the
code, spec acquisition happens at **five call sites**, and registration is only the first:

| Site | When it runs | Reaches the spec via |
|---|---|---|
| `registry/server.py:467` (`_provision_device`) | embedded, at registration | `_discovery_for(profile)` |
| `registry/server.py:582` (`_health_check_one`) | embedded, **every health cycle** | `_discovery_for(profile)` |
| `registry/pod_supervisor.py:100` (`spawn`) | embedded, on spawn and on `replace` | `self._spec_service` **directly** |
| `worker/runner.py:828` (`_fetch_spec`) | distributed, **cold** path | its own implementation |
| `worker/health.py:521` (`_fetch_spec`) | distributed, **health loop** | its own implementation |

Two of those five already share a seam — `_discovery_for`, whose docstring says provisioning
and the health loop "pick one here rather than branching inline" — so what a curated check
would actually have to be remembered in is **four** places, not five. That is still four.

**This project has already paid for the N-sites shape once, and says so in its own words.**
`worker/runner.py::_fetch_spec` carries the warning:

> Because there are two of them, an upstream kind added to one and not the other fails only on
> the path that was missed. This one is the *cold* path: a device registered while no manifest
> is cached reaches its pod through here, so an MCP upstream that discovers fine in the health
> loop would still never spawn.

That is this same failure with a different fact, and the count is now twice what it was when it
went wrong. It is not a risk to weigh against consolidation; it is the documented outcome.

**And there is a live instance of it in the table above.** `pod_supervisor.spawn` calls
`self._spec_service.fetch_spec(profile)` directly rather than through `_discovery_for`, so a
device whose `upstream_kind` is `mcp` and whose `spec_data` is empty gets the **OpenAPI** spec
service. Reachable: `server.py:584` calls `spawn` guarded only on `reachable and not
pod_active`, not on `spec_data`. The dispatcher exists, and one of the three embedded sites
already forgot it. See LR-47.

#### Decision: `resolve_spec_source(device)`, in `shared/`

One function that every acquisition site calls instead of reaching for `fetch_spec` itself. It
returns the curated snapshot when the device carries one — recomputing the hash from the
snapshot's own bytes, never trusting the catalog's, exactly as this section already requires —
and otherwise falls through to the existing live-fetch behaviour unchanged. The curated-vs-live
decision is made **once**, and a sixth call site added later inherits it instead of having to
remember it.

It lives in `device_mcp_gateway/shared/`, beside `keys.py` and `session_owners.py`, because the
sites span both `registry/` (embedded) and `worker/` (distributed) and both already import from
there. Explicitly **not** copied into each: that collapses four opt-outs into two and leaves
the identical failure at half the scale, which is the same trade this record's own history
argues against.

The distributed pair keep their deliberately different live-fetch implementations — concurrent
probing on the cold path, serial polling in the health loop, for the reasons `runner.py` gives.
What consolidates is the *decision*, not the fetch.

This is the same instinct as [ADR-0026](0026-service-identity-per-device.md) §2: the correlation
id is stamped at the guarded-egress builder rather than at each call site, so a new outbound
path inherits it by construction. One seam, chosen because the alternative is N authors each
remembering.

### 4c. A type may fix the host without minting the credential (amendment, 2026-09-01)

> **Not built**, like §4a and §4b. Recorded because it sat as a three-line note in a local
> plan file from 2026-08-31 to 2026-09-01 with no tracker row — the same "a decision nobody
> wrote down gets worked around rather than resolved" shape §7a and ADR-0026 were both caught
> by. Build it in the same pass as §4a/§4b; see the closing note on why.

§6's table has two rows and both of its columns move together:

| | Host | Credential | Claimed by |
|---|---|---|---|
| **Device type** (§1) | Tenant supplies | Tenant supplies | Tenant |
| **Provider-operated service** (§6) | Provider supplies | Provider mints, **per tenant** | Tenant |

The combination in between is unrepresentable: *the provider knows the address, the tenant
still brings their own credential*. A provider-hosted appliance image, a normalised front end
the tenant authenticates to with their own key, an endpoint whose location is provider
knowledge but whose access is not — none of these are §6 services, and none of them fit §1
either. `VersionFields` does not merely omit the case, it forbids it: *"Deliberately excludes
`hostname`/`base_url`/credential: those are the tenant's half (ADR-0020 §2), never the
provider's to supply here."*

#### Decision: host-fixing is declared at type level, independently of the credential model

A version carries `host_source: tenant | provider_fixed`. `fixed_base_url` (and, under the
conditions below, a bootstrap `fixed_spki_pin`) may be populated **only** when it is
`provider_fixed`, enforced as a write-time validation error by a `_check_host_source` beside
`_check_spec_path` and `_check_curated_document` in `repo.py` — same shape, same file, same
"raise, don't reconcile". `repo.py` rather than a pydantic validator in `schemas.py` for the
reason `_check_spec_path` already gives: the check must stay consistent with a table
constraint, and this one implies `host_source = 'provider_fixed' → fixed_base_url IS NOT NULL`.

Nothing about the credential moves. A `provider_fixed` type whose `auth_kind` is `api_key`
still takes the tenant's own key, and §5 is untouched — the catalog carries no secrets either
way. §6 remains what it is: a *service the provider operates and mints per-tenant credentials
for*, with all five of its obligations. §4c is the weaker, commoner thing §6 was being
stretched to cover.

**Why this is §4c and not §6a.** §4's governing sentence is that *a claimed device does not
silently follow* its type. §4a earns its place under §4 because version pinning and a live
reference are mutually exclusive; §4c is that same sentence applied to a different field — a
claimed device must not silently follow the catalog's idea of where the endpoint is, or of
what identity it presents. §6's table does need its third row, but that is a consequence of
this section, not its home.

#### The SPKI pin is bootstrap-only, and structurally so

This is the half that inverts if it is got wrong, so it is stated separately.

§6 gives tenant-held pinning a specific purpose: *"the tenant pins the provider's endpoint …
which is a control the tenant holds **over the provider**"*. The pin's whole job is to turn a
change of endpoint identity into an event requiring the tenant's attention. If the catalog
retained a write path to that field, a provider rotating a key and updating the catalog would
deliver the very event the pin exists to catch as ordinary configuration sync. That is **worse
than not pinning at all**: it looks protected and is not — the same shape as accepting a
`jwks_uri` from an unverified discovery document, a check quietly converted into a trusted
input from the party being checked.

So a curated pin is a **seed and nothing more**. It supplies the initial value so a tenant's
first contact is not blind trust-on-first-use, and after that the pin is the tenant's own
record with **no further catalog write path to it at all** — not "the catalog should not update
it", but cannot. A field the catalog can still write and is asked not to touch is a weaker
guarantee than one it cannot reach; the precedent is `SCOPE_DEVICES_WRITE_PLANNED`, which no
principal holds as a bundle member, admin included, and which is reachable only through
`write_planned.check_and_consume`.

**No detection machinery has to be designed for this**, which is the payoff of framing it that
way. Once the pin is tenant-owned, a provider changing keys is discovered exactly as any other
device's change is, at real connection time, by `security/fingerprint.py::decide` — whose own
docstring states the rule: *"a changed key **does not re-pin**. The approved `tls_spki_sha256`
stays put and the new value lands in `pending_tls_spki_sha256` … so a silent substitution
cannot launder itself into the baseline by being observed twice."* The device moves to
`STATE_PENDING`; under `POLICY_ENFORCE`, `quarantine_reason` refuses dispatch. Note the
converse, which is why the **SPKI** specifically is the field to lock: a certificate rotation
on the *same key* is `VERDICT_CERT_ROTATED` — informational, refreshes context, deliberately
does not interrupt. Ordinary renewal costs the tenant nothing; a key change is the event.

An ongoing catalog write to that field would therefore be, precisely, the laundering path
`decide()` was written to prevent, reached from a direction it does not defend.

#### `fixed_base_url` may ship without the pin

The two are independently valuable and the address half is much the simpler. If the seeding
mechanics need longer, ship `host_source` + `fixed_base_url` and leave `fixed_spki_pin` unset
and unimplemented; a `provider_fixed` type with no curated pin simply pins on first contact as
every device does today.

#### The `VersionFields` docstring is overridden in the same commit as the field

Its exclusion is a **stated rule**, not an omission, so shipping the field without revising it
does not leave the docstring incomplete — it leaves it **wrong**, from the moment the field
exists, with nothing to tell a reader which of two contradicting sources is current. The
docstring names what it used to forbid and why the exception now exists, in the commit that
creates the exception. This is the §7a lesson applied before rather than after: a written
precondition that quietly becomes false is the failure this record has already been corrected
for twice.

#### Build it with §4a/§4b

`_check_host_source` and §4b's `_check_curated_document` are the same validator shape in the
same file, and §4a's exclusivity does not exist yet either — so this is not a new check
mirroring an established one, it is two new siblings. Two written in one pass by one author
agree; two written months apart from the same reasoning rediscovered do not. All three are the
same underlying capability — **curation declaring a provider-known fact about a type, distinct
from what is left to the tenant** — surfacing on spec content and on host identity.

### 5. The catalog carries no secrets

A device type names the *kind* of credential a device needs (`api_key` in a header,
`oauth2_client_credentials`) and never a value. Under
[ADR-0018](0018-device-credentials-by-reference.md) the tenant supplies a reference into their
own secret store at claim time.

So a compromised catalog leaks the shape of an estate — which appliance models are in use —
and nothing that opens any of them.

### 6. The provider may operate services and offer them, and the tenant reaches out

A provider will want to **expose endpoints of their own** — an MCP server they run, an
OpenAPI service they host, a normalised front end to something awkward — and make them
available to tenants. Nothing in §1–§5 covers this: those entries are templates for hardware
the tenant owns.

The gateway already accommodates it without change. [ADR-0009](0009-mcp-passthrough.md)
settled that *a remote MCP server is a device, not a second entity*, and an OpenAPI service is
a device by construction. **A provider-operated endpoint is a device whose host happens to
belong to the provider**, and it enters a tenant's fleet through the same claim in §2.

So the catalog carries two kinds of entry:

| | Host | Credential | Claimed by |
|---|---|---|---|
| **Device type** (§1) | Tenant supplies | Tenant supplies | Tenant |
| **Provider-operated service** | Provider supplies | Provider mints, **per tenant** | Tenant |
| **Host-fixed type** ([§4c](#4c-a-type-may-fix-the-host-without-minting-the-credential-amendment-2026-09-01)) | Provider supplies | **Tenant supplies** | Tenant |

> The third row is [§4c](#4c-a-type-may-fix-the-host-without-minting-the-credential-amendment-2026-09-01),
> added 2026-09-01. As first written this table had two rows and both columns moved together,
> which made *"the provider knows the address, the tenant still brings their own credential"*
> unrepresentable and left §6 being stretched to cover it. A §4c type is **not** a
> provider-operated service and carries none of the five obligations below: the provider
> mints nothing, holds nothing per tenant, and the traffic is the tenant's own authenticated
> call to a host whose address happened to be provider knowledge.

Five properties make the second kind safe, and none of them is optional:

**The tenant still claims it.** It never appears in a tenant's fleet because the provider
assigned it. Assignment is an offer; claiming is the tenant's act, exactly as in §2. A service
that installed itself would be the provider writing into a tenant's registry, which is the
thing ADR-0017 removes.

**The credential is per tenant, always.** Never a shared secret. It is minted at claim time,
recorded as a reference in the tenant's own secret store ([ADR-0018](0018-device-credentials-by-reference.md)),
and revocable from either side. A shared credential would let one tenant present as another at
the service, which is the failure this whole architecture is shaped to avoid.

**The data flow is disclosed at the point of claiming.** Tool calls to this device leave the
tenant's stack and reach the provider — arguments, results and all. The claim screen says so
plainly, because a tenant enabling a provider-operated tool is making a data-residency
decision and should be making it knowingly rather than discovering it later.

**It is fingerprinted like any other device.** [ADR-0015](0015-endpoint-fingerprinting.md)
applies unchanged, and the tenant pins the provider's endpoint. The tenant can therefore
detect the provider's service changing identity underneath them — which is a control the
tenant holds *over the provider*, and is exactly the right direction.

**Egress is an ordinary allowlist entry.** ADR-0014 §3 already gives each tenant namespace an
egress allowlist for device CIDRs and ports; a provider-operated service is one more entry in
it. This is emphatically **not** an inter-tenant path and does not touch ADR-0014 §6 — traffic
goes tenant → provider, never tenant → tenant.

**The direction is what makes this consistent with ADR-0017 rather than a hole in it.**
ADR-0017 removes the provider's reach *into* tenant stacks. This adds the tenant's reach *out*
to a provider service, which is the safe direction: the tenant chooses it, the tenant can stop
it, and a compromise of the provider service exposes the traffic tenants chose to send it —
never their registries, their credentials or their other devices.

One consequence has to be accepted openly. **A provider-operated service is a genuinely
multi-tenant component in an architecture that otherwise refuses them** (ADR-0004), and it is
a cross-tenant aggregation point by definition. It therefore carries obligations the tenant
stacks do not: per-tenant authentication and authorization inside the service, no shared
mutable state across tenants, and its own isolation review. A provider who cannot meet those
should not operate shared services — the alternative is a per-tenant instance of the service,
which is more expensive and is always available as the conservative option.

### 7. Provider-plane storage is its own component, not the BFF's

The catalog gives the provider console its first persistent store, and the path of least
resistance — put it in the BFF's own storage — is closed here rather than left open.

The BFF is already audit writer and federation-credential relay. A persistent catalog store is a
third distinct responsibility in one component, and concentration of exactly this kind is what
[ADR-0012](0012-federation-credential-model.md) argued against when it declined to make the BFF
a token issuer as well. The argument does not weaken because the third role is storage rather
than signing.

So the catalog store is a **separate component with its own failure domain**, and
[ADR-0018](0018-device-credentials-by-reference.md) §7's discipline applies to it unchanged:

- its unavailability is a **named condition**, not something inferred from an empty catalog —
  a provider console showing no device types because a database is down must not look like a
  provider who has curated none;
- it does **not gate the console's readiness**, for §7's reason: everything except catalog
  reads still works, and taking the console out of service removes the view that would explain
  the outage;
- it has its own backup, availability and restore story, which is genuinely new operational
  surface and is the honest cost of this decision.

Where it physically lives — its own database, a managed service, a schema in an existing one —
stays a deployment choice. What is fixed is that it is not reached through the BFF's process
boundary and does not share the BFF's availability.

### 7a. The catalog needs a caller identity per tenant (amendment, 2026-08-28)

> **BUILT 2026-08-28.** Two caller classes in `device_mcp_catalog/app/auth.py`, a caller table
> in `config.py` that refuses startup when it is ambiguous, and `enforce_tenant_scope` as a
> router-level dependency covering path- and body-named tenants alike. The finding below is
> preserved in the past tense it was written in; what changed is stated at the end.

**Found trying to run the claim flow end to end for the first time**, in a lab where the
provider plane and a tenant stack are separate deployments on separate hosts. §2 is the half
of this record that had never been executed.

The catalog authenticates **one shared bearer token** for every route, and `auth.py` states
its own assumption plainly:

> *"Phase 1 has exactly one caller (the console BFF's `CatalogClient`) — see the plan's own
> reasoning for not building a scope model with no second caller yet to justify it."*

That reasoning was sound. What invalidates it is that **the second caller already exists in
the code**: the tenant console's own catalog routes — listing assigned types, claiming one,
and the upgrade offers — read the catalog *directly*, through the same client and therefore
the same token. They were built in the same phase as the assumption and never tested against
it, because no tenant stack had yet been wired to a catalog.

So deploying §2's tenant half as it stands means **every tenant's BFF holds the provider's
catalog token**, and the catalog authorizes nothing beyond possessing it:

- `GET /tenants/{tenant_id}/upgrades` takes the tenant from the **URL path** and returns
  `UpgradeOffer` objects carrying **`hostname`** — the tenant's actual device names, with the
  version each is pinned to. This is the sharp one: there is no `GET /claims`, so claims are
  readable only here, but this *is* the claim.
- `GET /tenants/{tenant_id}/assignments`, same path-parameter problem — which device types a
  competitor has been offered.
- `RecordClaim` takes `tenant_id` from the **request body**. A holder can record claims
  against another tenant, corrupting the provenance the upgrade-offer diff depends on.
- The same token reaches the curation and assignment routes. A tenant could curate a device
  type and assign it to themselves — or to anyone.

**Measured, not reasoned** (lab, two tenants, one shared token, asked about each in turn):

```
tenant1  assignments=['acme-storage-array']   upgrades=[]
tenant2  assignments=[]                       upgrades=[]
```

One credential, the tenant named in the path, and each answered for whoever was asked about.
Nothing checked entitlement.

#### Ranked by what actually leaks

Worth stating, because it changes what a fix must cover first and the obvious ordering is
wrong:

| Route | Leaks | Priority |
|---|---|---|
| `GET /tenants/{id}/upgrades` | **Tenant device hostnames** + pinned versions | **First** |
| `GET /tenants/{id}/assignments` | Which device types a tenant was offered — commercial intelligence about a competitor | Second |
| `GET /device-types` | The provider's whole catalogue | Third — this is the **provider's** product surface, not tenant data |

Scoping `assignments` alone is not enough, and scoping `device-types` — the one that looks
most like "too much data" — is the least urgent of the three.

One nuance that makes `upgrades` less than a total dump, and not much less: it returns only
claims whose pinned version differs from the current curated one. A tenant fully up to date
appears empty. In an estate where the provider keeps curating, being behind is the normal
state rather than the exception.

#### The tenant console is not the exposure, and that is the point

A tenant *operator* cannot reach any of this through the UI. The tenant BFF builds every
catalog call from `_tenant_id(request)`, which reads the BFF's **own configuration** — never
anything the browser sends — and the tenant console never calls the unscoped `/device-types`
at all. There is no parameter to tamper with.

The exposure is the **credential**, not the interface. Which means the boundary today is one
component's discipline rather than an enforced property, and every future route added to that
component has to remember it independently.

**The tenant console is not the problem, and that is the instructive part.** It already does
the right thing: its list route asks for *this* tenant's assignments rather than the unscoped
catalog, and its claim route refuses a type not assigned to it. The behaviour is correct and
the **enforcement is in the wrong layer** — it holds exactly as long as no BFF route forgets
it. This codebase has already made that argument once, in `rbac.py`, about the `console` role
and the backup scopes: *"A role that cannot express the scope moves it to the gateway, where a
console-side bug cannot undo it."* The same reasoning applies to the catalog, and this is the
same mistake one component along.

#### Decision: two caller classes, and the tenant is derived from the credential

| Caller | Holds | May |
|---|---|---|
| **Provider console** | one privileged catalog credential | curate device types, assign and revoke assignments, read everything |
| **A tenant's console** | its own credential, one per tenant | read the device types assigned **to it**, and record claims **for itself** |

Two rules make it work, and neither is optional:

**The tenant is read from the credential, never from the request.** A path parameter or a body
field naming a tenant is a *client assertion*, and this codebase has already settled how those
are treated everywhere else it matters — ADR-0017's `provider_subject` is "filled in from the
session's own subject and never taken from the request body", and §2's own `assigned_by`
follows the same rule. The catalog's `tenant_id` is the one place that pattern was not applied,
because with a single trusted caller there was nothing to distinguish. A request whose named
tenant disagrees with its credential's tenant is **refused**, not quietly reinterpreted — the
disagreement is the signal.

**A tenant caller cannot see the unscoped catalog.** `GET /device-types` enumerates every
curated type across the estate. Scoping only the assignments route would still let a tenant
read the provider's whole catalogue, which is estate shape they have no claim to. For a tenant
caller the type list *is* the assignment list.

#### What this costs, stated rather than glossed

The catalog gains its **first authorization model**, having deliberately had none — a caller
table mapping a credential to a kind and, for tenant callers, to exactly one tenant. That is
new surface in a component whose simplicity was a feature.

It also creates a **credential per tenant to provision, rotate and revoke**, which is real
operational weight and a new way for onboarding to fail. Two things make it the right trade
anyway: the alternative is a shared secret whose blast radius is the entire estate, and
ADR-0018's by-reference discipline already covers operator-provisioned secrets of exactly this
shape, so the mechanism exists.

Rejected alternatives, briefly. **Routing the tenant's catalog reads through the provider's
console** removes the tenant's token but makes a tenant unable to onboard a device while the
provider's console is down, inverting ADR-0017's dependency direction for no security gain —
the provider BFF would then have to authenticate tenants, which is this same problem moved.
**Mirroring assignments into each tenant's stack** replaces an authorization question with a
synchronisation one, and §7 has already ruled that unavailability must be a named condition
rather than something inferred from an empty list; a stale mirror is precisely an empty list
that cannot say why.

#### The property to test

Stated as a property because the positive case will pass on its own:

> **A tenant caller naming a tenant other than its own is refused, on every route that names a
> tenant.** Not filtered to an empty result, not silently rewritten to its own tenant —
> refused, and audited.

Test `upgrades` first and by name. It is the route that returns hostnames, and it is the one
an implementation is most likely to leave behind — `assignments` is the obvious one to scope
because it is the one the tenant console calls, and `upgrades` is reached by a different
component on a different schedule.

An implementation where each tenant only ever names itself is indistinguishable from a correct
one until someone names a neighbour. That negative test is the whole check, and it is the same
test that has now found three defects in this estate.

#### The shape worth remembering

**A documented assumption is not a guard.** `auth.py` named its own precondition — "exactly one
caller" — accurately and in writing, and the precondition was invalidated by code added in the
same phase, in another repository, that nobody re-read it against. The comment stayed true
about the past and became false about the present, and nothing failed, because the second
caller was built but never deployed.

This is the third finding in one day with one shape: [ADR-0017 §7a](0017-provider-authority-is-delegated.md)
(raising and deciding shared one scope), §7b (a console gate and a server gate that were never
asked to agree), and now a shared token spanning two trust domains. Each was invisible until
two things that had always run as one were finally deployed apart. **Deployment topology is a
test input**, and an estate that has only ever run as one process has not tested its own
boundaries.

#### What shipped, and the second gate nobody had counted

Built as decided, with three things worth recording because none was visible from the decision
alone.

**The enforcement is one dependency, not a rule each route follows.** `enforce_tenant_scope`
runs at the router, reads the tenant from the credential, and compares it against every tenant
the request names — in the **path** and in the **body**, since `RecordClaim` names one there.
Splitting those (a dependency for paths, a line in each handler for bodies) would have
recreated the finding above in miniature: one rule with two enforcement points, correct until
a handler forgets. A test discovers the routes from the OpenAPI schema rather than a list, so a
route added later is covered without anyone remembering to add it.

**A malformed caller table refuses startup**, deliberately unlike this service's database.
§7 requires an unreachable store to be a *named condition* the service stays up to report; an
ambiguous credential is not that. A store that is down cannot answer, and a caller table with a
token shared between the provider and a tenant — or between two tenants — answers **as the
wrong caller**. That is `BreakGlassConfigError`'s reasoning one service along, and it is why
`CatalogAuthConfigError` has no permissive mode.

**One misconfiguration remains invisible from here, and it needed the other side to close.**
The catalog cannot detect a tenant console configured with the *provider's* token: that request
authenticates correctly, as the provider, and every tenant's data is in reach. Nothing in the
caller table can see it, because nothing about it is wrong from this side. So the catalog gained
`GET /whoami` (`{kind, tenant_id}`, no database read), and the tenant BFF's `CatalogClient`
asks once, on first use, and disables catalog features rather than proceeding if the answer is
not its own tenant. Deliberately lazy rather than at startup: a startup probe would either make
the console's boot depend on the catalog being up, which §7 refuses, or pass silently whenever
the catalog was slow. "Could not check" and "checked and it was wrong" stay different
conditions — the first is retried, the second is not.

**And the gate that was actually holding.** `deploy/kubernetes/catalog/networkpolicy.yaml`
admits only the provider console's namespace, and its own comment asserted that a tenant
console "has no business reaching the catalog directly" — which was **false about the code**
and had been since the tenant routes were written. That comment is the reason the shared token
was never exploitable in a deployment: the credential gate was open and the network gate was
shut. Two gates, and the one holding was the one whose comment was wrong about why.

It is worth being precise about what that means, because "we were protected anyway" is the
wrong conclusion. The network policy was not a compensating control chosen for this risk — it
was correct for a topology in which the tenant half did not exist, and it would have been
opened by whoever first enabled a tenant's claim view, at which point nothing else stood in the
way. Enabling that path is now explicitly a two-part change, in order: provision the tenant's
own credential, then add its namespace. The policy file says so at the line that would be
edited.

### 7b. A credential can be correct and still be the wrong one (amendment, 2026-08-28)

> **BUILT 2026-08-28**, as decided — including the correction. The declaration
> (`X-Catalog-Tenant`) is enforced in `auth._check_declaration` before the scope rules; the
> catalog gained a metrics plane for this one condition, with a `severity: page` rule in
> `deploy/kubernetes/catalog/monitoring.yaml`; `/whoami` was demoted to a diagnostic and the
> BFF's client-side gate removed. **The open timing question below resolved itself** — see the
> note at the end of it.

#### The gap §7a cannot see, by construction

§7a derives the tenant from the credential and refuses a request that names another. That closes
**forgery at request time**: a caller asserting a tenant its credential does not support.

It says nothing about the credential being the wrong one *before any request is made* — a
provisioning-time misdelivery that puts tenant B's catalog credential, or the provider's, into
tenant A's console. From the catalog's side that request is indistinguishable from a correct
one: a credential arrived, it identified a tenant, and everything agreed. **The mechanism
working exactly as designed is the failure mode.** Different risk, different moment, and §7a's
text does not reach it — not by oversight, but because a mechanism whose job is to trust the
credential's claim cannot also audit that claim's delivery.

The shape is already half-recorded next door. [ADR-0024 §10](0024-tenant-provisioning-is-a-request.md)
measured the nine manual steps of connecting a tenant, and step 9 is *"wire the catalog:
address, credential, `TENANT_ID`, and an egress port"*, with its failure listed as **"🔇 times
out; reads as 'the catalog is down' while it is healthy."** That is the failure when the
*address* is wrong. When the **credential** is wrong there is no symptom at all: it does not time
out, it works — for the wrong tenant. It belongs in that table's silent column, and it is the
worst entry in it.

#### Why this is recorded rather than only coded

§7a closed with **"a documented assumption is not a guard"** — a precondition can be true,
written down accurately, and become false later without anything failing observably.

Undocumented code is not the safe side of that lesson; it is strictly worse. A stale comment at
least gives a future reader something to be suspicious of. An unexplained second check gives
them a reason to delete it — and the reasoning will look sound: *the catalog already enforces
tenant-from-credential, so a client-side comparison of the same two values is redundant.* Every
step of that is correct except the conclusion, and nothing in the code says why. **The record is
what makes the deletion stop looking correct.**

#### Correction: the check belongs on the server

What was built asks `GET /whoami` and lets the **client** decide. That is a client-side gate on a
server-enforced property — the exact shape [ADR-0017 §7b](0017-provider-authority-is-delegated.md)
found (a console gate and a server gate that were never asked to agree), and the same
wrong-layer error §7a corrected two paragraphs earlier in this very document. Building §7a's fix
and reintroducing its finding in the same change is not a distinction worth defending.

So invert it. **A tenant caller declares the tenant it believes it serves, on every request, and
the catalog refuses when that declaration disagrees with the credential.** Declared, not asked.
Three things follow:

- a client that forgets to check cannot skip the check, because it is no longer the client's;
- the refusal happens where the counter, the log and the route gate already are;
- `/whoami` survives as a **diagnostic** — *what am I holding?* — which is what it is genuinely
  good for, rather than as a gate.

The declaration is not authority and must not be mistaken for it. The credential still decides
what the caller may do; the declaration only supplies the **second** assertion the catalog needs
in order to notice that two things disagree. A caller that omits it is refused rather than
admitted — an optional declaration is a check with an opt-out, which is the same thing as no
check for exactly the deployment that got it wrong.

#### Failure behaviour: loud, and on the alert plane

**Refuse every catalog-dependent route.** Already the built behaviour: `CatalogMisconfigured`
subclasses `CatalogUnavailable`, so it arrives as §7's named 503 rather than a 500, and it stays
**non-fatal to the console** for §7's own reason — a credential mistake must not take out a
tenant's entire UI when everything except the catalog still works.

**And raise a dedicated alert**, reusing the pattern ADR-0023 established for break-glass rather
than inventing a third notification mechanism: a counter, and a `severity: page` rule beside
`MCPBreakGlassActivated` in `deploy/kubernetes/prometheus-rules.yaml`. A console holding another
tenant's credential is a *this-should-never-happen* condition and gets that treatment, not a log
line nobody is reading.

**The cost, stated because it is not free.** Neither component is a Prometheus target today. The
BFF *queries* Prometheus for its monitoring view and exposes no `/metrics` of its own; the
catalog has neither a `prometheus_client` dependency nor a ServiceMonitor. Putting this on the
alert plane makes one of them a scrape target for the first time.

It should be the **catalog**: one per estate rather than one per tenant, already the side the
check moves to, and it keeps every tenant console off the scrape path. That is new operational
surface in a service whose separate failure domain is deliberate (§7), and it is accepted here as
the honest price of not building a second alerting mechanism for one condition.

#### Where the credential comes from — the other half is already written

[ADR-0024 §10](0024-tenant-provisioning-is-a-request.md) already says: *"This is where ADR-0020
§7a's credential comes from."* Enrolment mints the per-tenant credential, revoking an enrolment
revokes it, and that record states plainly that **"the two records should be built together —
§7a states the property, this states the lifecycle, and neither is complete alone."**

§7a never pointed back. It does now. And this section is the third piece: what happens when that
lifecycle is executed **incorrectly**. Enrolment is what should make misdelivery impossible;
§7b is what catches it in the window before enrolment exists — and afterwards, on the paths
enrolment does not own: a manual rotation, a restored secret, an operator editing a mounted file
by hand.

#### Open: when the check runs

Deliberately not settled.

- **Startup only** catches provisioning, which is the named risk, and nothing else. A credential
  rotated in later is never re-examined — and the entire premise of this section is that a wrong
  credential *works*, so nothing else will notice.
- **Startup plus every credential reload** covers the supported rotation path, and is the floor.
- **Plus an independent periodic re-check** is what covers the unsupported paths — the hand-edited
  file, the restore putting back an older secret — which is precisely the class of drift this
  record keeps finding.

The lean is all three, with a long period, because this is a should-never-happen check and not a
health probe.

What argues against settling it now is that the correction above may dissolve the question
entirely. **Under a declared-tenant design the comparison happens on every request**, because the
declaration is on every request — there is no cached verdict to go stale, no reload to hook, and
no heartbeat to schedule. If that holds, the answer to "when" is "always", and the timing
question was an artefact of checking once and remembering the answer. That is worth confirming
against a real deployment's request pattern before being written down as settled, which is why
it is recorded as open rather than resolved by argument.

> **Resolved by construction, 2026-08-28.** It held. The declaration is set once on the BFF's
> long-lived client and sent with every catalog request; the catalog compares it every time and
> caches nothing. All three candidate schedules — startup, credential reload, periodic heartbeat
> — are subsumed, because a credential swapped in by any means, supported or not, is checked on
> the next request that uses it. Recorded here rather than deleted because the *reason* is the
> useful part: the question only existed while the check was something a client did once and
> remembered, and moving the check to the server removed the state that needed a schedule. **A
> caching decision was masquerading as a scheduling problem.**

### 8. Why this comes before ADR-0017 in the build order

Once a provider cannot reach into a tenant's stack, the catalog is how they do their job.
Building ADR-0017 first would leave a window in which the provider has lost the ability to
help and gained no replacement for it, which is the shape of change that gets reverted under
operational pressure.

## Consequences

- **Positive: the provider gets a real write surface** with no cross-tenant reach — the thing
  D2 was actually asking for.
- **Positive: tenant onboarding stops requiring appliance expertise**, which is the ordinary
  product benefit and probably the one a customer notices.
- **Positive: the provider gains a product surface** — services they operate become claimable
  by every tenant without a bespoke integration each time, which is likely where the commercial
  value of the catalog actually is.
- **Positive: provider knowledge accumulates somewhere.** Fingerprint expectations, egress
  requirements and working auth shapes currently live in whoever set up the last one.
- **Negative: new backend surface at every layer** — provider-plane storage, a curation API, an
  assignment model, a claim flow in the tenant console, and versioning. This is the largest
  net-new build in the reorientation.
- **Negative: a tenant in an estate loses the ability to register anything they like.** For
  some customers this is governance and for others it is a limitation; §3 accepts it, and the
  escape hatch is a conversation rather than a setting.
- **Negative: a provider-operated service concentrates risk** the rest of the architecture
  spreads. It is the one component where a single compromise touches many tenants, and §6's
  obligations are the price of having it at all.
- **Negative: catalog versioning is a migration problem in miniature** — N tenants on M
  versions of a device type, each needing an upgrade path. Deliberately accepted over the
  alternative in §4.
- **Negative: claiming becomes a second construction path to keep correct.** §4b refuses to
  reach a snapshot through the `spec_url` path with an optional field, so the gateway gains a
  device-construction path that must stay behaviourally aligned with the fetch-driven one
  without sharing its preconditions. That is real duplication, taken deliberately over a single
  function with two modes and no way to tell which it is in.
- **Negative: a curated spec is bulk the catalog must carry forever.** §4a's snapshot means
  every version of every type holds a copy of its document rather than a link to one, and
  those copies are immutable by construction, so the store only grows. Inline in PostgreSQL
  keeps ADR-0025's single restore story intact and is the default for that reason; the
  object-storage escape hatch for large documents buys row size at the price of a second
  store to back up and restore in the right order.
- **Negative: a per-tenant credential can be delivered to the wrong tenant, and §7a cannot
  tell.** §7b names the gap — misdelivery at provisioning rather than forgery at request time —
  and closing it costs a declared tenant on every tenant-caller request, plus making the catalog
  a Prometheus scrape target for the first time so the condition reaches the alert plane rather
  than a log. New surface in a service whose separate failure domain is deliberate, taken over
  building a second notification mechanism for one condition.
- **Negative: the catalog needs its own authorization model, which §7 did not anticipate.**
  Making it a separate component gave it a network boundary and therefore a caller identity
  question, and phase 1 answered it with a single shared token on the strength of having one
  caller. §7a is what that costs once the tenant half of §2 is real: a credential per tenant
  to provision and rotate, in a component whose lack of an authorization model was a feature.

## Alternatives considered

**Provider registers directly into a tenant's registry.** The obvious design, and the reason
ADR-0016 existed. Rejected because it requires the standing cross-tenant write authority that
ADR-0017 removes — it is the thing this ADR exists to replace.

**Catalog as a pure documentation artefact** — a published list of supported appliances with
setup instructions, and free-type registration everywhere. Rejected because it puts the
provider's operational knowledge in prose, where it cannot carry a fingerprint expectation or
an egress requirement into the tenant's stack as data.

**Tenant-authored catalog entries shared back to the provider.** Appealing, and probably right
eventually for large customers with unusual estates. Deferred: it needs a review and trust
model of its own, and building it now would mean designing that model before a single
first-party entry exists.

**Claimed devices follow the catalog version automatically.** Simpler, keeps every tenant
current, and removes the migration problem in §4. Rejected on blast radius — the failure mode
is a provider's typo changing every customer's fleet simultaneously.

## Open questions

**All four were answered in the 2026-08-20 design pass; the record was not updated at the time
and the resolutions were restored here on 2026-08-21 from the working tracker
(`~/.claude/plans/adr-open-questions-tracker.md`).**

- ~~**Which backing store the catalog uses.**~~ **Resolved: PostgreSQL.** A managed cloud
  instance where one is available, self-hosted HA on-prem as the default otherwise. SQLite
  stays available but as an **explicitly small-scale-only** option, not a supported path to
  growth — §7 gives the catalog its own failure domain, and a store that cannot be replicated
  cannot honour that at estate scale. This is the deployment dependency the implementation
  order (`README.md`) weighs 0020 as the largest item for.

- ~~**Whether assignment is per tenant or by group.**~~ **Resolved: per tenant.** Tedious at
  scale and correct anyway — a group (tier, region, contract) is a *property* a tenant happens
  to hold at a moment, and binding entitlement to it means a tenant's fleet changes as a side
  effect of an administrative reclassification nobody connected to their devices. Grouping can
  be layered on later as a bulk-assignment convenience over per-tenant records; it cannot be
  unpicked from underneath them.

- ~~**Whether a tenant can be required to keep a provider-operated service.**~~ **Resolved:
  unclaiming is always the tenant's right**, in the direction this leaned. The alternative is a
  device the tenant cannot remove from their own fleet, which contradicts §2 directly and, more
  practically, is the provider asserting standing authority inside a tenant stack — exactly
  what [ADR-0017](0017-provider-authority-is-delegated.md) removes. A provider who needs a
  monitoring agent in place makes that a contractual condition, not a technical one the tenant
  cannot exercise.

- ~~**How an upgrade is offered.**~~ **Resolved: reuse tool-diff governance.** The catalog does
  not need a second, parallel notion of "a change the tenant should look at" — the
  breaking/non-breaking classification and approval pattern already built for device tool
  changes covers it. A catalog upgrade surfaces **on the fleet list**, is **never blocking**,
  and is **never scheduled or forced**. That keeps §4's version pinning meaningful: pinning is
  the tenant's, and an upgrade is an offer they accept, which is also why the blast-radius
  objection to automatic following (see the rejected alternative above) does not come back
  through the notification path.
