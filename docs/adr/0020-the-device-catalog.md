# ADR-0020: The provider's write path is a catalog; tenants claim from it

- **Status:** Proposed
- **Date:** 2026-08-17
- **Answers:** D2 (does the provider console offer device writes?), open since ADR-0013.
- **Prerequisite for:** [ADR-0017](0017-provider-authority-is-delegated.md) §1 — see §7.

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

### 7. Why this comes before ADR-0017 in the build order

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

- **Where provider-plane storage lives.** The provider console has had no persistent store of
  its own; this gives it one, which is a new operational component with its own backup and
  availability requirements.
- **Whether assignment is per tenant or by group** (tier, region, contract). Per tenant is
  obviously correct and obviously tedious at scale.
- **Whether a tenant can be required to keep a provider-operated service** — a monitoring
  agent, say — or whether unclaiming is always the tenant's right. Leaning always theirs, since
  the alternative is a device the tenant cannot remove, which contradicts §2.
- **How an upgrade is offered** — notification, a console prompt, or a scheduled window — is a
  product question that interacts with §4's version pinning.
