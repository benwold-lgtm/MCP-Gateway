# Operator documentation — Provider Guide, Tenant Guide, and the rest

*Plan, not a deliverable — the guides themselves will be `docs/provider-guide.md` and
`docs/tenant-guide.md`. It lives in `docs/` rather than `.claude/` for one reason: **`.claude/`
is gitignored** (`.gitignore:31`), so nothing there is version-controlled, reviewable in a PR, or
visible to anyone else. The previous copy of this outline sat outside the repository entirely and
went stale against ADR-0017 without anyone noticing.*

> ## ⚠️ Read before drafting anything — this outline predates ADR-0017
>
> Written before the tenancy re-architecture. **Its highest-stakes section documents features
> that no longer exist**, and its recommended starting point was the most-superseded part of it.
>
> | Mechanism it builds on | In ADRs | In code |
> |---|---|---|
> | `provider:invoke` | as superseded history | **0 references** |
> | `provider:credentials` | as superseded history | **0 references** |
> | `act-on-tenant` | as superseded history | **0 references** |
>
> All removed in #139 and shipped as removed in v0.3.5. References to "§11b" mean ADR-0013 §11,
> which [ADR-0017](adr/0017-provider-authority-is-delegated.md) superseded.
>
> **What survives:** the two-document split and its reasoning; the Tenant Guide's trust section
> (it rests on ADR-0013 §9, which stands); §4's backlog; §5's tunables table and its discipline.
> Sections below are marked ✅ current, ⚠️ needs rewriting, or ⛔ superseded.

---

## 0. Sequencing — what can honestly be written, and when

The binding constraint is not effort. It is that **most of the Provider Guide describes
architecture that is decided but unbuilt**: the catalog is build item 6, delegated authority is
item 7, the provider console is item 8. Writing it now repeats the "documentation ahead of
reality" mistake §4/D5 already identifies, one layer up.

| Order | Work | Why now / why not yet |
|---|---|---|
| 1 | **README corrections** | ✅ Done. It described OIDC as a future swap when it shipped, and omitted `credential_ref` and `tools/tenant_id.py` entirely |
| 2 | **Tenant Guide** | ✅ Writable today — every part of it ships: device registration, fleet sessions, RBAC in your own boundary, backup/restore, fingerprinting, what your audit shows |
| 3 | **Glossary** (`docs/glossary.md`, D1) | ✅ Writable today, and overdue — "Tier" already means two unrelated things across ADR-0014 and ADR-0017 |
| 4 | **Tunables reference** (§5) | Build incrementally, one entry per mechanism, in the commit that wires its config key |
| 5 | **Provider Guide** | ⛔ Blocked on build items 6–8. Its estate sections have no subject yet |
| 6 | **Root README tenancy rewrite** (D5) | ⛔ Deliberately deferred until MT ships as a release |

---

## 1. Provider Guide — ⚠️ needs rewriting against ADR-0017 before use

**Do not draft from this section as written.** The structure is reusable; the mechanisms are not.

### Prerequisites — ⚠️
- ~~Provider IdP step-up-conditioned custom claim (§11b)~~ ⛔ **superseded.** ADR-0017 §7 Tier 0
  needs nothing shared between the two identity systems — no common issuer, no exchange, no
  tenant-side IdP at all.
- Tier 2 (Cilium) as a precondition for a multi-tenant estate — [ADR-0014] ✅ still current, but
  see the naming collision in D1.
- ~~Provider plane as a second, separately-administered IdP~~ ⛔ **superseded** by ADR-0017: the
  provider console holds no credential for a tenant's data plane at all.

### Onboarding a tenant — ⚠️ rewrite against ADR-0024
Provisioning is now a **record**, not prose: [ADR-0024](adr/0024-tenant-provisioning-is-a-request.md).
The console *requests* and *imports*; it never provisions. Covers the identifier, the overlay,
the out-of-band secrets package, both checklist gates and the four-state progression. Onboarding
in the guide becomes a walkthrough **of that record**, not a separate account of the same steps.

### Day-to-day operation — ⚠️
- Estate health view ✅ — but note ADR-0017 §5 *forbids* building it by querying N tenant APIs.
- ~~`act-on-tenant`~~ ⛔ **removed.** Replaced by delegation: an operator enters *that tenant's*
  console with a credential the tenant granted.
- Search/inventory across tenants ⚠️ — the `(tenant, hostname)` compound identity survives;
  how a provider reaches it does not.

### Elevated actions — ⛔ SUPERSEDED IN FULL
The entire section — `provider:invoke`, `provider:credentials`, the grant-duration tiers, the
step-up flow — describes deleted code. Its replacement is
[ADR-0017 §7](adr/0017-provider-authority-is-delegated.md)'s tier model plus
[ADR-0022](adr/0022-agent-initiated-device-writes-are-plan-bound.md)'s plan-bound writes,
neither of which is built. **This was the outline's recommended starting point; it is now the
one section that cannot be written at all.**

### Backup & restore — ⚠️
Rewrite against [ADR-0018](adr/0018-device-credentials-by-reference.md) and
[ADR-0011's supersession markers](adr/0011-backup-and-restore.md). ~~Ciphertext vs
portable, `backup:export-portable`, the passphrase~~ ⛔ all gone. What stands: dry run by
default, per-item outcomes and reasons, `on_conflict`, warnings at the top, and a gate on the
apply. Add [ADR-0025](adr/0025-the-catalog-has-its-own-durability-story.md) when the
catalog exists.

### Incident response — ✅ mostly current
Reads from `failure-modes.md` / `runbook.md`. Add break-glass per
[ADR-0023](adr/0023-gateway-break-glass-attribution.md) once built — individually
attributable, 90-day expiry, loud audit.

### Offboarding — ✅ current
ADR-0013 §10 stands. Add ADR-0025 §4: the catalog's assignment rows go too, and an archive
predating the offboarding is a named condition on restore.

### Guardrails to restate — ✅ still the right idea
Update the list: no fan-out writes; **the provider holds no credential for a tenant's data
plane**; no live per-tenant credential on the monitoring path; `devices:write-planned` never in
`ROLE_SCOPES`.

---

## 2. Tenant Guide — ✅ writable today, start here

Structure survives intact. Everything it covers ships.

### Getting started ✅
Registering devices (including `credential_ref`), fleet sessions, RBAC within your boundary —
[rbac-roles.md], [ADR-0008], [ADR-0018].

### What a provider can and cannot do to your environment ✅ — and the answer got *better*
Rests on ADR-0013 §9, which stands. **Rewrite the framing:** under ADR-0017 the honest answer is
no longer "elevated access, used rarely" but *"authority over your environment is delegated by
you, and expires."* That is a stronger transparency story than the outline assumed it would be.

### FAQ ✅
Keep all three questions; the second one's answer changes shape with the above.

### Your own operations ✅
Role/scope management; what Tier 2 isolation changes for you.

---

## 3. Gaps before either guide is complete

- ⚠️ **Tier 2 namespace-list generation** — ADR-0024 now decides this: a checklist gate on the
  provisioning request, not automation. Describe the gate.
- ⛔ ~~§11b's resolution is brand new — draft it first~~ — superseded; do not.
- ✅ **ADR-0015 (fingerprinting)** — belongs in **both**: the Tenant Guide (what a fingerprint
  warning means for your device) and the Provider Guide (catalog fingerprint expectations,
  ADR-0020 §3).
- ⚠️ **Per-tenant configurable audit disclosure** — still a recommendation, not shipped. Describe
  what exists.

---

## 4. Documentation & complexity backlog

| # | Item | Status |
|---|---|---|
| D1 | No glossary. **"Tier" already means two unrelated things** — ADR-0014's network isolation tier and ADR-0017's provider-access tier — and ADR-0024 §5 now names any interface collapsing them as a defect. Build `docs/glossary.md`: one entry per term, pointing at the defining ADR, multi-sense terms disambiguated at the top | **Open — promoted.** Highest-value writable doc after the Tenant Guide |
| D2 | ADR index staleness | **Resolved**, and held: the register now carries statuses, the supersession map and the implementation order, and was reconciled 2026-08-21 |
| D3 | The guides are an outline, not a document | **Open** — see §0 for what is writable when |
| D4 | Create-tenant form needs progressive disclosure | **Open.** ADR-0024 §5 fixes *what* the request captures, which makes this purely presentational — and ADR-0024's two-meanings-of-Tier warning makes grouping load-bearing, not cosmetic |
| D5 | Root README frames tenancy as single-tenant-per-stack only | **Open — deliberately deferred.** Still accurate for what ships. Revisit with the guides once MT releases. ⚠️ Do not confuse with the *other* README staleness, which was real and is now fixed: it described OIDC as a future swap, and omitted `credential_ref` and `tools/tenant_id.py` |

---

## 5. Tunable-parameters reference — build it incrementally, never ahead of the code

An operator needs one place listing every tunable duration, its default and where to change it —
not four ADRs' worth of prose about why a number was chosen.

**Verified, not assumed:** `read_cache_ttl` is declared in `cfg.py` and read nowhere. There is no
key yet for plan-digest validity or break-glass expiry.

**So: one entry per mechanism, in the same commit that wires that mechanism's config key** — the
discipline that keeps the ADR index current, applied to tunables. One location (`docs/tuning.md`).

| Parameter | Default | Source | Wired? |
|---|---|---|---|
| Credential resolver cache TTL (networked) | **300s** | ADR-0018 §7c | No — `read_cache_ttl` declared, unused |
| Mounted-files / Lite resolver cache | 0, read-through | ADR-0018 §7c | Decided, not a tunable |
| Plan-digest validity | **7 days** | ADR-0018 §6 | No |
| Break-glass credential expiry | 90 days | ADR-0023 §3 | No |
| Break-glass reactivation-flag threshold | not picked — needs usage data | ADR-0023 §3 | No |
| Standing-consent maximum term | **no default ever chosen** — only the mechanism | ADR-0017 §3 | No |
| Reconciliation grant lifetime | explicitly left open | ADR-0022 step 4 | No |

Standing consent is the one place where even the mechanism's own ADR never picked a starting
number the way break-glass got 90 days. Genuinely open, not merely unwired.

**Also unwritten, and sequenced rather than missing:** secret-store HA and recovery guidance.
ADR-0018 §7's refuse-on-stale decision leans on HA as the availability answer, and ADR-0025 §5
notes the precedent exists for Redis and not for the secret store. It is not a doc gap to close
today — **only `MountedFilesResolver` is implemented**, and §7's machinery is scoped to networked
backends. Write it in the commit that builds one.

---

## 6. Starting point

⛔ ~~Draft the Provider Guide's Elevated Actions section first~~ — the single worst place to
start now, for the reason in §1.

✅ **Start with the Tenant Guide**, then the glossary. Both are writable today against shipped
code, both are entirely absent, and the Tenant Guide is the document an actual customer reads.
