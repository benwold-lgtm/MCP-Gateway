# ADR-0011: Backup and restore — ciphertext by default, portable behind its own scope

- **Status:** Accepted
- **Date:** 2026-08-11
- **Related findings:** F-34 (credential encryption + key rotation), F-57 (hash-chained audit)
- **Builds on:** [ADR-0002](0002-redis-control-plane.md) (Redis holds the control plane),
  [ADR-0004](0004-single-tenant-per-stack.md) (one stack = one tenant = one backup domain)

## Context

Every durable thing the gateway knows lives in one Redis: the device registry, the stored
credentials for each device, and the governance history of how each device's tool surface
has changed. [ADR-0002](0002-redis-control-plane.md) made that a deliberate choice, and
[failure-modes.md](../failure-modes.md) already lists Redis as the stack's defining SPOF.
What it does not list is a recovery path. A corrupted, ransomed, or fat-fingered `FLUSHALL`
today means re-registering every device by hand, with credentials that may only exist in
that Redis.

Three constraints shape the answer.

**Credentials are encrypted at rest under `MCP_SECRET_KEY` (F-34), and that key is not in
Redis.** So a byte-level Redis dump is already a form of backup — and already useless
without the key, which is the correct property. Any export we build inherits the same
question: does the archive travel with the ability to decrypt it, or not? Both answers are
legitimate for different jobs, and they are not the same risk.

**Restoring is not the inverse of exporting.** The registry is not inert data — registering
a device validates its URL against the egress policy, translates and bounds its spec,
derives a spec hash, and emits audit. A restore that writes hashes straight into Redis
would bypass every one of those gates, and would happily reinstate a device whose
`base_url` the current egress policy now forbids. It would also be the perfect primitive
for an attacker who has `backup:write` but could not otherwise register anything.

**A backup that cannot be restored is theatre**, and the failure mode is silent: the
operator learns the archive was unreadable at the moment they most need it. Fernet
ciphertext under the wrong key fails cleanly at decrypt, but only if something actually
attempts a decrypt.

## Decision

The gateway owns backup and restore as a first-class admin API, in **two archive kinds**
gated by **three scopes**, with a **fail-closed preflight** on every restore.

### 1. Two archive kinds

| Kind | Credentials | Scope required | Job it does |
|---|---|---|---|
| **Ciphertext** (default) | Left encrypted exactly as stored | `backup:read` | Routine/scheduled backup, restore into the same stack or any stack sharing `MCP_SECRET_KEY` |
| **Portable** | Decrypted, then re-encrypted to a caller-supplied passphrase | `backup:read` **and** `backup:export-portable` | Migration to a stack with a different key; disaster recovery when the key itself is lost |

**An archive never contains `MCP_SECRET_KEY`.** A ciphertext archive is worthless to
someone who steals only the archive — that is the point of the default. A portable archive
is a complete set of live device credentials protected by one passphrase, so it gets its
own scope, is never the default, and is audited as the significant event it is.

### 2. Portable encryption is specified now, not left to implementation

- **Argon2id** for passphrase → key (available in `cryptography` 48.0.1; no new dependency).
- **`m=64 MiB, t=3, p=4`**, and these parameters are **written into the envelope**, not
  assumed by the reader. Raising the cost later must not make every existing archive
  unreadable.
- **A random salt per archive**, in the envelope alongside the parameters.
- A **passphrase-strength floor** enforced at export, also recorded in the envelope.

### 3. Restore is fail-closed, and the preflight is a gate rather than a documented assumption

Before a restore writes anything, it decrypt-tests the **entire** archive. Any failure
aborts the **whole** restore — never a partial apply that leaves the registry half-migrated
between two key generations.

The preflight differs by kind, deliberately:

- **Ciphertext archives** are tested against the target stack's `MCP_SECRET_KEY`. A key
  mismatch is the expected failure and must be named as such.
- **Portable archives** are tested against the supplied passphrase only. They are
  key-independent by design; demanding the target's `MCP_SECRET_KEY` for one would defeat
  the purpose.

**Every envelope carries a canary token** — a known plaintext encrypted under the same key
or passphrase as the archive body. Without it, an archive containing only devices with
`auth_type: none` has no ciphertext to test, and the preflight would pass while proving
nothing. The canary makes the check total.

### 4. Restore goes through `register_device`

Restore replays each device through the ordinary registration path — egress policy, spec
translation and bounds, spec hash, audit — never a raw Redis write. A restore can
therefore *fail on a device* that the current policy no longer permits, and that is correct
behaviour, reported per device rather than swallowed.

- **`dry_run=true` is the default.** A restore that changes state is something the caller
  has to ask for explicitly.
- **`on_conflict=skip|overwrite|fail`** for a hostname that already exists. No default that
  silently overwrites live configuration.

### 5. What is in scope

**Included:** the device registry (`devices:all`, `device:{h}:config`) and governance
history (`device:{h}:tools_change` — the deliberately un-TTL'd record of tool-surface
changes, which is the part with no other source of truth).

**Opt-in:** dead-letter streams (`device:{h}:calls:dead`). Operationally valuable during an
incident, unbounded and mostly noise otherwise.

**Excluded, on purpose:** everything reconstructible or ephemeral — claims and leases,
worker membership and heartbeats, the assignment and call streams, open sessions,
idempotency markers, rate-limit counters, and the TTL'd manifest cache. Restoring a stale
claim or a half-consumed stream would actively harm a fresh stack.

### 6. Audit covers all four calls

Export **and** restore, **both** archive kinds, **including `dry_run=true`**, emit a
hash-chained audit record (F-57) bound to the authenticated principal. A ciphertext export
is a complete dump of every credential in the stack; if previewing a restore is worth a
record, taking that dump certainly is. A dry run is also the natural reconnaissance step
before a real one, so it is exactly the event a responder wants in the chain.

## Consequences

- **Positive:** the stack's defining SPOF finally has a recovery path; a fresh stack can be
  stood up and repopulated; the safe archive is the default and the dangerous one is
  explicitly requested, scoped, and logged; restore cannot be used to bypass registration
  gates; a wrong-key restore fails loudly and completely instead of half-applying.
- **Negative / cost:**
  - Three new scopes to provision, and `backup:read` alone is a meaningful grant — the
    holder can exfiltrate every device's URL and configuration even without the key.
  - Portable export is a genuine credential-exfiltration primitive. It is mitigated by
    scope, non-default, audit, and a passphrase floor — not eliminated.
  - Restore is slower and can partially fail per device, because it uses the real
    registration path. Accepted: the alternative bypasses the egress policy.
  - Argon2id at `m=64 MiB` makes export and restore visibly slow. Intended.
- **Follow-ups:**
  - **Operators must still back up `MCP_SECRET_KEY` out-of-band** — `failure-modes.md` §6
    already says so, and no archive kind changes it.
  - A DR runbook, verified by restoring into a genuinely fresh stack rather than a
    re-registered one.
  - **Sequencing note:** once BFF-side provider federation ships
    ([ADR-0012](0012-federation-credential-model.md)), the BFF gains its *own* registry of
    providers and their credentials. That is a separate store on the other side of a trust
    boundary, and it needs its own backup story — this ADR does not cover it.

## Alternatives considered

- **Redis `BGSAVE`/RDB snapshots only:** rejected as the answer, though still worth running.
  An RDB is all-or-nothing, tied to a Redis version and topology, includes the ephemeral
  state we explicitly want to drop, and offers no path to a stack with a different key.
- **Always decrypt on export (one archive kind):** rejected — it makes every routine backup
  a plaintext credential dump, which is the exact property F-34 was built to avoid.
- **Never decrypt on export (ciphertext only):** rejected — it makes `MCP_SECRET_KEY` loss
  unrecoverable and offers no migration path between stacks. The two jobs are different;
  one scope separates them.
- **Restore by writing Redis keys directly:** rejected — faster and simpler, but bypasses
  the egress policy, spec bounds, and audit, and would be a privilege-escalation primitive
  for a `backup:write` holder.
- **`dry_run=false` by default:** rejected — the destructive direction should never be the
  one you get by omission.
- **A documented "check your key first" assumption instead of a preflight:** rejected on
  review. The failure it prevents is silent and occurs at the worst possible moment; a
  paragraph in a runbook is not a control.
