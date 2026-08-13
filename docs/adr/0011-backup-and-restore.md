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

**Added 2026-08-13 — the endpoint fingerprint** (`fingerprint` block per device;
[ADR-0015](0015-endpoint-fingerprinting.md)). It sits alongside the governance history for
the same reason: a pin *looks* like a runtime measurement but is a baseline somebody is
trusting — TOFU established it, or a human approved it. Omitting it does not lose a fact
the new stack re-derives; it silently re-runs trust-on-first-use against whatever now
answers, so **the archive is what keeps the control alive across a restore**. The restore
half never re-pins: where the archive and a live record disagree, the live pin stays and
the disagreement is reported.

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

## Implementation notes (2026-08-11)

Three things the build found that this ADR had not accounted for. Recorded here rather than
silently absorbed, because two of them change what the decision above actually guarantees.

**1. "Credentials are encrypted at rest" is true of one mode, not both.** Distributed mode
encrypts before writing to Redis; **embedded mode keeps `DeviceConfig.auth_config` as
plaintext JSON** and encrypts a layer lower, in the SQLite store. So a ciphertext archive
built by exporting the stored value verbatim would have been a real ciphertext archive on
one mode and a **plaintext credential dump on the other** — from the same safe-by-default
call, with nothing in the response to tell them apart.

The archive's credential field is therefore defined as *ciphertext under whatever seals
this archive*, and export normalises to it: distributed values are decrypted and re-sealed
under the primary key (which also collapses a rotation window), embedded plaintext is
encrypted. **A ciphertext export with no `MCP_SECRET_KEY` configured is refused with 409**
rather than quietly downgraded — the archive would otherwise carry the safe label and the
dangerous contents.

**2. §4's guarantee did not hold as written.** "Restore replays through `register_device`,
so the egress policy still applies" — it did not. `validate_target_url` was called by the
*route handler* in `api/devices.py`, and `registry/server.py` never called it. Nothing
exploited this while the handler was registration's only caller, but a restore built on
that sentence would have been precisely the `backup:write` privilege-escalation primitive
§4 exists to deny. Filed as **F-67** and closed with the restore build: the gates moved to
`registry/validation.py` behind one `validate_device_registration(...)` that both callers
use. The decision stands; the code had to be made to match it.

Two consequences of §4 worth stating plainly, both visible once restore existed:

- A restored device comes back **unprovisioned**. Registration re-fetches the spec and
  re-spawns the pod, so a device unreachable at restore time lands with a `spawn_error` and
  `reachable: false` (F-66) until it can be contacted. Restoring into a genuinely cold site
  therefore reports success on devices that are not yet serving, which is honest but worth
  saying in the runbook.
- `tools_revision` and the last tool-change record cannot travel *through* `register_device`
  — it starts a device at revision 0. They are written immediately after the replay, which
  is sound because they are governance metadata *about* a registration rather than inputs
  *to* one: the egress policy has nothing to say about them, so nothing is bypassed. Without
  it a restored device reads to a polling client (F-41) as having rolled its tool set back.

**3. "Argon2id makes export and restore visibly slow" is overstated.** At `m=64 MiB, t=3,
p=4` a derivation measures ~0.12s, and it is performed **once per archive** — the whole
body is sealed under one derived key — not once per credential. The cost is real but not
operationally visible, so it should not be cited as a reason to avoid the portable kind.

### What is still unverified (2026-08-11, after v0.3.2)

The Follow-ups above name a DR runbook "verified by restoring into a genuinely fresh stack."
That is now tracked as **[TG-7](../testing-gaps.md#tg-7--disaster-recovery-restore-into-a-genuinely-fresh-stack--closed)**,
together with two neighbouring gaps the build surfaced —
**[TG-8](../testing-gaps.md#tg-8--backup-and-restore-at-fleet-scale)** (everything here is
tested at 2–3 devices; export is one synchronous response over the whole registry) and
**[TG-9](../testing-gaps.md#tg-9--backup-across-a-key-rotation-on-a-live-distributed-stack)**
(export and restore mid key-rotation, the scenario the `is_current()` trap came from).

**TG-7 is now closed (2026-08-11).** A portable archive was restored into a genuinely fresh
stack on separate hardware — new Redis, new pods, a **different `MCP_SECRET_KEY`** — and a
`tools/call` on a restored device returned live upstream data using the restored credential.
The follow-up above ("a DR runbook, verified by restoring into a genuinely fresh stack") is
discharged; the runbook is
[runbook.md § Rebuild a stack from nothing](../runbook.md#rebuild-a-stack-from-nothing-disaster-recovery).

**What the walk changed about this ADR.** Nothing in the archive format or the restore
algorithm — preflight, replay through the registration gates, manifest rebuild and
`tools_revision` carry-over all behaved as designed. What it exposed is that this ADR framed
the recovery story around the *archive*, and the archive turned out not to be the hard part.
Three things it deliberately does not carry each stopped a rebuild before any restore ran:
per-device TLS trust material (the gateway fails closed at startup without it), three
environment variables that live only as hand-applied additions to the source cluster, and
non-Kubernetes DNS resolution. §6's "back up `MCP_SECRET_KEY` out-of-band" was right in kind
but too narrow — it is a *set* of out-of-band dependencies, now tabulated in the runbook.

The sharpest of them is worth repeating here: without `MCP_ALLOW_PRIVATE_TARGETS`, restore
refuses every private-address device and reports a **correct policy refusal**. The response
body cannot distinguish "your new stack is misconfigured" from "the policy legitimately
rejects this device" — which is a direct consequence of §4 replaying through the real gates,
and the price of that decision rather than a defect in it.

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
