# ADR-0025: The catalog has its own backup, availability and restore story

- **Status:** Proposed
- **Date:** 2026-08-21
- **Related:** [ADR-0020](0020-the-device-catalog.md) — names this gap explicitly in its own §7,
  as "the honest cost of this decision"; this record is the resolution.
  [ADR-0011](0011-backup-and-restore.md) — the restore-correctness properties reused below,
  and the gate.
  [ADR-0018 §7](0018-device-credentials-by-reference.md) — the failure-domain discipline
  ADR-0020 already extended to the catalog.
  [ADR-0013 §10](0013-two-plane-tenancy-and-the-provider-plane.md) — offboarding, and the rule
  that backups participate in it.

## Context

[ADR-0020](0020-the-device-catalog.md) makes the catalog the provider's first persistent store
— a PostgreSQL database, per its own 20.1 resolution — and says plainly that this is new
ground:

> it has its own backup, availability and restore story, which is **genuinely new operational
> surface** and is the honest cost of this decision.

Nothing wrote that story. [ADR-0011](0011-backup-and-restore.md) mentions the catalog zero
times; it was never in scope, and extending its scope after the fact would blur what it was
carefully written to cover — particularly now that
[ADR-0018](0018-device-credentials-by-reference.md) has superseded the parts of it that were
about secrets.

**What needs a durability story here is narrower than a device registry, and the reason is
worth being precise about.** Per [ADR-0020 §2](0020-the-device-catalog.md), an *assignment* —
"this type is offered to this tenant" — writes to the provider plane. A *claim* — the tenant
supplying a host and a credential — registers the device **in the tenant's own stack, by their
own credential, in their own audit chain**. The catalog never holds a claim.

[ADR-0020 §5](0020-the-device-catalog.md) states the consequence as a decision rather than
leaving it to inference: *"The catalog carries no secrets."* A device type names the *kind* of
credential a device needs and never a value, so a compromised catalog "leaks the shape of an
estate — which appliance models are in use — and nothing that opens any of them."

The catalog's durable content is therefore exactly three things:

1. **type definitions**
2. **their version history** — [§4](0020-the-device-catalog.md) makes a claimed device stay
   pinned to the version it claimed, so old versions cannot simply be discarded
3. **assignment records**

No secrets, ever, by construction. That is a materially simpler problem than the gateway's own
backup story, not a smaller version of the same one.

## Decision

**Back up type definitions with their full version history, and assignment records. Nothing
else — there is nothing else durable in the catalog.**

### 1. Reuse ADR-0011's restore-correctness properties, all five

The properties that survived [ADR-0011](0011-backup-and-restore.md)'s own supersession were
never about secrets. They are domain-agnostic statements about what a good restore does, and
[ADR-0018 §5](0018-device-credentials-by-reference.md) enumerates exactly which ones stand:

- **Dry run by default**; the destructive direction never reachable by omission.
- **Per-item outcomes and reasons**, not just counts.
- **`on_conflict` modes** for what the target already has.
- **Warnings surfaced at the top of the report**, not buried per row.
- **A gate on the apply** — time-boxed, not single-use, and not covering the dry run.

Applied to catalog rows — types, versions, assignments — instead of device registrations. Same
properties, same reasons, different object.

### 2. The apply is gated; the dry run is not

The fifth property above is the one it would be easiest to skip here, and it is the one this
record set can least afford to skip. **A catalog restore rewrites what every tenant in the
estate is offered, in one action.** That is the largest blast radius any provider-side
operation has, in a set of records built on the principle that the provider holds less and
reaches less.

So the gate takes the shape ADR-0011's did after ADR-0018 narrowed it: **on the apply, on
destructiveness rather than disclosure, time-boxed rather than single-use, and not covering the
dry run.** Reading the catalog and previewing a restore disclose nothing that
[ADR-0020 §5](0020-the-device-catalog.md) has not already established is safe to disclose;
overwriting it is the act worth gating.

The scope is provider-plane and its exact name is left to implementation, on the same reasoning
[ADR-0022](0022-agent-initiated-device-writes-are-plan-bound.md) used for
`devices:write-planned`: name it for the mechanism, and never add it to a standing role bundle.

> **Not requiring a plan digest, deliberately.** A catalog restore is exactly the blast radius
> [ADR-0018 §6](0018-device-credentials-by-reference.md) exists for, and layering the digest on
> top would be defensible. It is declined here because §6 is unbuilt (build item 4) and making
> the catalog's durability wait on it would leave build item 6 with no restore story at all —
> the precise gap this record closes. Revisit once §6 ships; the dry-run/apply split above is
> already the shape a digest would slot into.

### 3. The one genuinely new conflict: a still-claimed version

[ADR-0020 §4](0020-the-device-catalog.md) makes claimed-version pinning a deliberate guarantee:
a provider's typo or a bad migration must not change every customer's fleet at once. **A
catalog restore that silently drops a still-claimed version breaks that guarantee from the
other direction** — the tenant's claim would reference a version that no longer exists.

Restore checks assignment and claim references against the versions present in the archive
being restored. Any still-claimed version missing from the resulting state is **reported
explicitly and requires an operator decision** — skip removing it, restore it alongside the
rest, or abort — rather than being resolved automatically in either direction.

This is the fingerprint-warning instinct from ADR-0011 applied to a different object: a
condition the operator must see, surfaced at the top of the report, never a silent removal.

### 4. Offboarding: a catalog backup participates in the shred

The catalog holds assignment records keyed by tenant, so a departed tenant leaves rows behind.
[ADR-0013 §10](0013-two-plane-tenancy-and-the-provider-plane.md) already settled the principle
for the gateway's own archives, in words that transfer without modification:

> archives of a departed tenant … belong *inside* the shred. **A backup expiring on its own
> independent schedule is a hole straight through this decision.**

**Offboarding removes that tenant's assignment rows from the catalog.** No crypto-shred
apparatus is introduced for them: §5 of ADR-0020 means there is nothing here to shred *from* —
these rows are metadata, not content encrypted under a per-tenant key, and building the ADR-0013
§10 machinery for them would be ceremony without a secret behind it.

**What does need handling is the archive that predates the offboarding.** A restore from such
an archive reintroduces rows for a tenant who has left, and that must be a **named, surfaced
condition requiring an operator decision** — the same treatment as §3's still-claimed version,
for the same reason. It is not a credential leak; it is a record of which appliance models a
departed customer ran, which is the commercially sensitive shape
[ADR-0019](0019-opaque-tenant-identity.md) minted opaque identifiers to avoid leaking in the
first place.

### 5. Backup mechanism, and what HA does not do

**Standard PostgreSQL point-in-time recovery — WAL archiving plus periodic base backups — kept
separate from whatever HA topology 20.1's PostgreSQL choice selects.**

**HA solves availability; it does not solve recovery.** A live replica takes over when a node
dies. It does not help with an accidental `DROP`, a bad migration or a mistaken bulk
reassignment, all of which replicate to every HA node exactly as faithfully as a correct write.

This is the distinction [kubernetes-architecture.md](../kubernetes-architecture.md) already
draws for Redis, where periodic snapshot backups for point-in-time recovery sit alongside — not
inside — the HA guidance. **It is not yet drawn for the secret store**, which
[ADR-0018](0018-device-credentials-by-reference.md)'s own open questions flag as outstanding:
neither `README.md` nor the architecture guide mentions it. So this record follows a precedent
that exists in one place and is missing in another, and says so rather than claiming a
settled convention it would be borrowing on credit.

### 6. No encryption apparatus, and why that is a conclusion rather than an omission

ADR-0011's ciphertext/portable machinery — the Argon2id KDF, the envelope, the canary, the
passphrase — existed because an archive contained live credentials. **Nothing here ever does**,
by the division ADR-0020 §2 draws and §5 states. A catalog archive is closer to ordinary
application configuration than to anything ADR-0011 or ADR-0018 had to reason carefully about.

Stating this explicitly matters because the absence would otherwise read as an oversight to the
next reader, who arrives from two records that took credential handling extremely seriously.

## Consequences

- **Positive:** closes the gap ADR-0020 §7 names against itself, so build item 6 lands with a
  durability story rather than acquiring one afterwards. Reuses proven restore-correctness
  properties instead of designing new ones. Confirms — rather than assumes — that the catalog's
  backup story is structurally lower-risk than the gateway's ever was: no KDF, no envelope, no
  passphrase, nothing to get wrong in the way credential handling requires care to get right.
- **Negative / cost:** a genuinely new backup and restore mechanism to build and operate,
  distinct from the gateway's own. Real work, even if simpler work. Two conflict conditions —
  the still-claimed version and the departed tenant — need an operator-facing surface with no
  precedent to copy verbatim, only properties to reuse. And PITR for PostgreSQL is operational
  surface a provider must actually run: WAL archiving that silently stops is a backup that
  silently is not one.
- **Follow-ups:** the WAL-archiving and base-backup cadence ships as a sensible default and is
  tuned from operating history, the same treatment now given to
  [ADR-0018](0018-device-credentials-by-reference.md)'s cache TTL and plan-digest validity.
  The wording and placement of both conflict warnings is console design, not backend behaviour,
  and belongs with build item 8. Revisit the plan-digest question in §2 once
  [ADR-0018 §6](0018-device-credentials-by-reference.md) ships. **Separately and not this
  record's to fix:** the secret store's own HA and recovery guidance is still missing, per §5.

## Alternatives considered

- **Treat the catalog as covered by ADR-0011/0018 by extension.** Rejected: both are carefully
  scoped to gateway and tenant-side data, with a credential-bearing history that shaped every
  decision in them. The catalog is a separate store, in a separate plane, with a data model that
  has no credential concern at all. Stretching their scope to cover it would blur what made them
  precise — and ADR-0011 has just been narrowed, not widened.

- **Rely on HA alone, no separate backup.** Rejected for the reason §5 gives: HA is an
  availability property, not a recovery one. An accidental `DROP` replicates perfectly.

- **Silently reconcile a still-claimed version, or a departed tenant's rows, by a fixed rule.**
  Rejected in both directions. A silent choice, however well-intentioned, removes the operator's
  chance to catch something wrong before it matters — the reasoning behind ADR-0011's fingerprint
  warnings and ADR-0018 §6's refuse-on-drift, and the same instinct ADR-0024 applies to
  provisioning gates that guard silent omissions.

- **Crypto-shred a departed tenant's assignment rows under a per-tenant key**, mirroring
  ADR-0013 §10 exactly. Rejected: maximum consistency, but the machinery exists to make
  *encrypted content* unrecoverable while leaving a hash chain verifiable. These rows are
  metadata with no secret behind them and no chain over them. Deleting them is the operation;
  a key to destroy would be ceremony.

- **Gate nothing, and leave catalog restore to provider-side console RBAC.** Rejected: it is the
  single highest-blast-radius provider action in the design — it rewrites every tenant's offers
  at once — and leaving it unnamed in a record set built on the provider holding less would be
  conspicuous by its absence.
