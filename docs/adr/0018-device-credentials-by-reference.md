# ADR-0018: Device credentials are held by reference, never at rest in the gateway

- **Status:** Proposed
- **Date:** 2026-08-17
- **Supersedes:** most of [ADR-0011](0011-backup-and-restore.md) — see §5.
  Affects [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) §5b and §10,
  and removes the `provider:credentials` tier from §5/§8/§11a — see §6.

## Context

The gateway stores each device's upstream credential — an API key, an OAuth client secret, a
bearer token — encrypted under one stack-wide key, `MCP_SECRET_KEY`, and decrypts it on every
dispatch.

That single fact is load-bearing for a surprising amount of the system. Because the registry
contains credentials:

- a backup is a **complete credential dump**, which is why exporting one needs its own
  elevated, single-use grant;
- archives need two kinds — ciphertext for same-key restores, portable for crossing key
  generations — which needs an Argon2id KDF, an envelope format, a canary, a passphrase, and a
  two-request download because a browser download cannot read the header a minted passphrase
  arrives in;
- offboarding needs **crypto-shredding**, and the archives have to be inside the shred or they
  are a hole through it;
- the provider, who operates the stacks, holds the key that opens every tenant's secrets — the
  uncomfortable fact underneath ADR-0013 §5b's insistence that a ciphertext archive is a
  credential dump *for the provider specifically*.

Every one of those is a correct response to the premise. None of them questions it.

## Decision

### 1. The registry stores a reference and an identity, not a secret

A device record carries a **credential reference** — an opaque URI naming a location in a
secret store — and the gateway holds a **workload identity** allowed to dereference it:

```
credential_ref: "vault://t-7f3a91c4/devices/prism#api-key"
```

The gateway resolves the reference at dispatch time and does not persist the result beyond the
request. **For an operator-provisioned secret it never holds a decryptable copy at rest** —
and that scope is not a caveat, it is the boundary, set out in §1a.

**The secret store belongs to the tenant, not to the provider.** This is what makes the change
a security improvement rather than a relocation: a provider who cannot read the store cannot
read the credentials, whatever they hold in the gateway.

### 1a. References cover operator-provisioned secrets; gateway-minted rotating ones are outside

A reference model assumes **the tenant is the sole writer of a secret's lifecycle.** The
gateway reads; somebody else provisions and rotates. Every property in §1 follows from that
assumption, so where the assumption does not hold, neither do the properties.

It does not hold for a credential the **gateway itself mints**. An OAuth2 provider that
rotates refresh tokens hands back a new one during a token exchange, and the gateway is the
only party present when it does. There is nobody else to write it, so it must be persisted by
the gateway — which is why `OAuth2Auth` already carries a `CredentialsChangedHook`, and why
the release notes carry a fix for the release where it was not persisted and every such device
died on restart.

The line is therefore **operator-provisioned versus gateway-minted**, and it is a real category
boundary rather than a scope drawn to make the problem smaller:

| | Provisioned by | Rotated by | Under ADR-0018 |
|---|---|---|---|
| API key, OAuth2 `client_secret`, `password` | Tenant | Tenant | **By reference.** §1 holds in full |
| OAuth2 `refresh_token` | Gateway, mid-exchange | Gateway | **Encrypted at rest** under `MCP_SECRET_KEY`, and **never exported** in any archive (§3) |

**State the consequence without softening it.** For a device using OAuth2 with refresh-token
rotation, compromise of `MCP_SECRET_KEY` is not a reduced version of the pre-ADR-0018 risk —
**it is the identical risk, untouched.** A live refresh token mints access tokens indefinitely,
so it is worth precisely what the credential blob was worth, and this ADR does nothing for it.
The correct summary is not that §1 is weakened at the edges: **§1's central claim holds for
static secrets and does not hold at all for rotating ones.**

One consequence follows and is accepted deliberately:

- **`MCP_SECRET_KEY` does not go away**, and neither does key rotation, for any deployment with
  a rotating-token device. It becomes unnecessary only for a fleet that is entirely
  operator-provisioned.

**The archive question is settled, and settled by exclusion.** A rotating token is **never
exported, in any archive, unconditionally** — see §3. That is a change from this section's
first draft, which said an archive of such a stack is still a credential dump and left the old
`backup:*` apparatus alive to protect it.

**What is *not* settled** is the at-rest question, which is the one this section exists to name:
a live refresh token is still held encrypted under `MCP_SECRET_KEY` in the running registry, and
compromise of that key still costs exactly what it did before ADR-0018. Closing *that* needs a
resolver which can **write** — turning §3's open question about console writes into a
requirement. Excluding the token from archives narrows the blast radius to a running stack; it
does not shrink it to nothing, and this ADR does not claim otherwise.

### 2. Resolution is an interface, and the backend is a deployment choice

`CredentialResolver` has one method — reference in, material out — and at least three
implementations:

| Backend | For |
|---|---|
| Kubernetes Secret / CSI driver | The default enterprise path; the tenant's namespace already scopes it |
| External manager (Vault, cloud SM) | Tenants with an existing secret discipline |
| Local file, mode 0600 | Lite and embedded mode |

This is what stops the decision raising the floor for small deployments. **The shape is the
same everywhere** — a reference in the registry, resolution at dispatch — and only the
implementation varies. Lite gains a file it already effectively has; it does not gain a
dependency on a secrets product.

**A resolver failure is not automatically a device failure.** A bad reference is that
device's problem; an unreachable store is the fleet's, and the two must not present
identically. §7 makes that distinction, because getting it wrong turns a brief outage in a
shared dependency into a long one across every device.

### 3. Backup becomes configuration backup

An archive contains device definitions, tool-change history and credential *references*. It
contains no credentials, so:

- there is **one kind of archive**, not two;
- there is **no passphrase**, no KDF, no envelope, no canary, and no two-step download;
- there is **no elevated grant for export** — an archive is configuration, and configuration
  is `devices:read`-shaped;
- restoring into a different stack requires that stack to be able to resolve the references,
  which is an honest and visible failure rather than a silent one.

**Restore keeps its dry run.** That was never about credentials; it is about a plan being read
before it is applied, and it has already caught real mistakes.

**There is no exception for rotating-token devices.** An earlier draft made one: a stack with
such a device would keep the whole `backup:*` apparatus, so an archive was configuration only as
far as §1a's first row extended. That conditional is **withdrawn**. A gateway-minted rotating
token is **excluded from every archive, unconditionally**, and the claims above hold for every
stack rather than for entirely-operator-provisioned ones.

#### Why exclusion beats a mixed-fleet conditional

**The conditional keeps the crypto apparatus alive as a rarely-exercised path.** Passphrase,
KDF, envelope and canary would survive as code that fires only for stacks that happen to own a
rotating-token device — which in this project is a specific and well-evidenced liability, not a
general worry. The live-cluster verification standard exists *because* a 1321-test suite passed
while the feature under it did not work. A protection path that almost never executes is the
exact shape of code that rots quietly and fails the one time an incident depends on it.

**The guarantee the conditional protects frequently does not hold anyway.** Many OAuth2
providers invalidate the previous refresh token the moment a new one is issued. A token backed
up a week ago can already be dead server-side by the time anyone restores it, for reasons no
archive design controls. Carrying full protection machinery to preserve seamless restore, when
seamless restore is not reliably available, is a bad trade twice over.

**It is the same category this project already excludes**, and the principle simply had not been
carried through. `backup/export.py` omits claims and leases, worker membership, assignment and
call streams, sessions, idempotency markers and rate-limit counters, and says why: *"Restoring a
stale claim or a half-consumed stream would actively harm a fresh stack, so the omission is a
feature, not a gap."* Its rule is that the archive carries **registration inputs, not runtime
state.** A refresh token is gateway-accumulated runtime state, not a tenant-declared input — it
was slipping through only because it is stored inside `auth_config` next to genuine registration
inputs. Excluding it applies the existing rule; it does not add an exception to it.

#### What "excluded" means precisely

**Only the live token value.** Everything that makes the device a device is still exported as
ordinary configuration: its registration, its `credential_ref`, and — per §1a's first row — the
operator-provisioned `client_secret` or `password` that reference points at. Nothing about the
device's identity or its ability to be re-established is lost.

That distinction is what bounds the cost, and the cost differs by grant:

| Grant | After restore |
|---|---|
| `client_credentials` | **Seamless.** `client_secret` survived, so the gateway re-runs the token exchange on first use. No human, indistinguishable from normal operation |
| `password` | **Seamless.** `username` and `password` survived; same path |
| `refresh_token` | **Needs re-authorization.** The token *was* the credential; nothing surviving the archive can re-mint it |

(The `authorization_code` grant is out of scope for this gateway — it needs an interactive
redirect — so the affected population is exactly `grant_type=refresh_token` devices, not every
OAuth2 device.)

**The one real cost must be visible, not discovered.** A `grant_type=refresh_token` device
arrives from a restore unable to authenticate, and that must surface as an explicit tenant-facing
state — *this device needs reconnecting* — reported by the restore itself and visible in the
device's status afterwards. It must not be a device that looks restored and fails on its first
tool call. This is the same standard §7 sets for a credential failure at dispatch: the operator
is told what is wrong and where, rather than being handed a symptom. ADR-0011's per-device
outcomes and reasons, which §5 keeps, are the reporting channel — this is a new outcome kind in
an existing mechanism, not new machinery.

### 4. Offboarding is a secret-store operation

ADR-0013 §10 buys erasure by destroying a per-tenant content key so that hashes survive and
content does not. For *audit* content that remains exactly right and is untouched here.

For *credentials* it stops being the gateway's problem. Deleting the tenant's namespace in the
secret store revokes every device credential, whatever archives exist and wherever they are.
The archive-retention hole — a backup expiring on its own schedule, outliving the shred —
closes because there is nothing in the archive to outlive.

**Not "at once", on the mounted-files backend.** An earlier draft of this section said
revocation takes effect immediately. Measured on a live cluster (2026-08-19), it does not:

- **Deleting** a Secret does **not** reach a pod that already has it mounted. The kubelet has
  no source to re-project from, so the last projected content stays readable in the volume —
  observed unchanged for 4+ minutes, and there is no mechanism that would ever remove it.
- **Modifying** a Secret *does* propagate, in ~30–60s, because the kubelet re-projects it.
- The deletion only bites at **pod restart**, and then it bites hard: the replacement pod gets
  `FailedMount` and never becomes Ready.

So for a mounted-files deployment, offboarding is: delete the secret **and then restart every
pod holding the mount**. Until that restart the credential is live in the volume, in a pod the
operator believes they have just deprived of it. Where revocation must be immediate, rotate or
empty the secret's *key* rather than deleting the secret — that path re-projects and is the one
this ADR should recommend. A networked backend does not have this gap, because it holds nothing
locally to go stale.

### 5. What survives of ADR-0011

ADR-0011 is not superseded wholesale, and the parts that survive are the parts that were about
*restore correctness* rather than about secrets:

| ADR-0011 decision | Fate |
|---|---|
| Dry run by default; the destructive direction never reachable by omission | **Survives** |
| Per-device outcomes and reasons, not just counts | **Survives** |
| `on_conflict` modes | **Survives** |
| Fingerprint warnings surfaced at the top of the report | **Survives** |
| Ciphertext vs portable archive kinds | Removed |
| Argon2id KDF, envelope, canary, passphrase | Removed |
| Generated passphrase + `X-Backup-Passphrase` header | Removed |
| `backup:export-portable` scope | Removed |
| `provider:credentials` grant | Removed as a category — see §6 |
| A gate on `backup:write` (restore) | **Survives**, on destructiveness rather than disclosure — but time-boxed, not single-use (§6) |

### 6. `provider:credentials` disappears as a category, and its mechanism must re-earn its place

ADR-0013 §5 defines two elevated grants. `provider:invoke` exists because calling a tool
acts on a customer's infrastructure. `provider:credentials` exists for one reason, stated
plainly in ADR-0013 §5b: a backup is a credential dump, so reading one must be single-use and
step-up-gated.

Under §3 there is no credential dump. So the category has nothing left to name:

- **An archive is configuration.** Export is `devices:read`-shaped, per §3.
- **A credential reference is not a credential.** It names a location in a store the provider
  cannot read. It is an ordinary device field.
- **Rebinding the gateway's workload identity** is a deployment operation — a ServiceAccount,
  a Vault role — and belongs to cluster RBAC and GitOps, not to a BFF grant. Putting it in the
  grant vocabulary would be the provider granting themselves access to a tenant's store, which
  is the thing §1 exists to prevent.

**`provider:credentials` is therefore removed, not narrowed.** A narrowed version would be a
category whose only members are things already covered by `devices:read`, kept alive because
deleting a tier feels like a loss.

#### What that does and does not remove

The tempting conclusion is that every member goes with the category, and that is too fast. Look
at what was actually in the class: `backup:read` and `backup:export-portable` —
credential-bearing — but also **`backup:write`**, which is restore.

Restore was gated because it travelled in the credential class. It has an independent reason to
be gated, and that reason survives §3 untouched: **restore overwrites a tenant's device
registry.** Its risk is destructiveness, not disclosure.

But inheriting the credential class's *gate* along with its membership would be the same
mistake in reverse. The reason survives; the mechanism has to be chosen for it, which is the
subsection below.

So the elevated taxonomy loses a tier and gains a clearer axis. It was implicitly
**credential-bearing vs not**; it becomes **blast radius**:

| | Grant | Duration | Why |
|---|---|---|---|
| Acts on one device, reversibly | `provider:invoke` | Time-boxed | ADR-0013 §5, unchanged |
| Overwrites the registry | `backup:write` | **Time-boxed, repeatable** | Destructive, not credential-bearing — every call audited |
| Reads configuration | `devices:read` / `backup:read` | Ordinary | Nothing elevated remains |

That axis is the better one. It explains why restore is gated without appealing to a fact
about restore that is no longer true, and it does not need a grant category to hold a single
member.

#### Restore is time-boxed and repeatable, not single-use

Saying restore keeps its gate leaves the shape of that gate implicit, and the two candidates
behave very differently. It is **time-boxed and repeatable** — the `provider:invoke` class —
and not single-use.

The reasoning single-use rested on does not transfer. Disclosure does not decay: once an
archive has been read the harm is done and cannot be undone, so rationing reads is a real
bound. A destructive write is different in kind — **accountability for it is fully discharged
by recording each act, not by rationing how many times an operator may try.** Every restore
call is already audited individually, with its `dry_run` flag, its `on_conflict` mode, its
per-device counts and its fingerprint warnings. A second restore inside the window is a second
audit record, not an unobserved one.

And the legitimate workflow is iterative by design: dry run, read the report, adjust
`on_conflict`, dry run again, then apply. ADR-0011 made the dry run default precisely to
encourage that loop. Charging a fresh step-up for each step taxes the careful path and
reduces blast radius by nothing.

**The current implementation is worse than that argument suggests, and is the evidence for it.**
Consumption is recorded during grant verification, so it fires on *any* request bearing the
scope — and the dry run carries `backup:write` exactly as the apply does. The first dry run
spends the elevation and the apply that follows is refused. The safe call burns the budget and
the destructive one is blocked, which inverts the intent. That is not a tuning problem; it is
what happens when a bound designed for reads is applied to a read/write pair.

##### What replaces it is a better control

Repeatable does not mean unbounded, and the useful bound is on **what** is applied rather than
on how many attempts are allowed:

- **An apply must reference the dry run it was previewed from.** The request carries the digest
  of a plan the gateway produced, and the gateway refuses to apply if that plan no longer
  matches the current inputs. Unlimited dry runs, and every destructive act bound to a plan a
  human actually read.
- This must be **enforced server-side.** The console already computes a preview signature and
  marks a report stale when the inputs move, which is a good affordance and no bound at all —
  it lives on the side of the boundary the operator controls.
- The absolute window, the existing route rate limits, and per-call audit continue to apply.

That combination targets the actual failure — applying something other than what was reviewed
— where single-use only ever targeted the count.

##### The digest commits to the whole request, by construction

The rule is **not** "the archive plus `on_conflict` plus `include_deadletters`". It is:

> The digest commits to the **entire canonicalized apply request**, minus only fields that are
> purely informational and cannot affect what is applied. That exclusion list is **empty
> today**, and adding to it requires a stated reason.

The enumerated version is wrong for a reason worth recording, because it is a shape this
repository has already been bitten by: **a list of fields is a dependency that must be
remembered at a site that does not exist yet.** Whoever adds the next restore parameter has to
also remember to add it to what the digest covers, and nothing fails if they don't — the same
failure shape as a guard that must be attached per route rather than being structural. Binding
to the request as a whole covers new parameters by construction, and the person adding one has
to argue *out* rather than remember to argue *in*.

The concrete case that proves the enumeration insufficient, and would equally have been missed
by any list written before the parameter existed: a dry run under `on_conflict=skip` reports
*"3 conflicts, nothing overwritten"*, a human reads that and approves, and the apply arrives
with the same archive and `on_conflict=overwrite`. An archive-only digest calls that a match
while performing a categorically more destructive act than the one reviewed.

Two mechanical requirements follow:

- **The gateway computes the digest over its own parsed, canonicalized representation**, at dry
  run and again at apply — never over the client's bytes. Otherwise the client chooses the
  canonicalization, and equality becomes a property of their serializer.
- **Canonicalization is specified** — key ordering, numeric form, absent-versus-null — because
  a digest whose inputs re-serialize differently is a correctness bug that presents as a
  spurious refusal, and the fix under time pressure is always to weaken the check.

##### Validation and execution are one call, with no validate endpoint

The apply request carries the digest, and the gateway validates it and performs the write
**inside that single synchronous request.** There is no separate validate step and no
`POST /admin/restore/validate` to add later — a two-round-trip shape would open precisely the
window this project has already lost twice, in the DNS-rebind race in the SSRF guard and in the
stream-cursor ordering fix.

There is a reason the check is structurally gap-free here rather than merely carefully
sequenced, and it is worth stating: **the digest commits to the request, and the request cannot
change during its own handling.** There is no external state for the validation to race
against. That is a property of what was chosen to bind to, not of how carefully the handler is
written — which is the distinction between the two earlier bugs and this.

##### The digest binds the operation, not the target

The digest guarantees the **requested operation** was not altered between review and execution.
It does **not** guarantee the target registry was frozen, and it is not intended to.

The case: a dry run reports device X will be skipped as a conflict; someone deletes X out of
band; the apply now creates X instead of skipping it. The digest is byte-identical and the
real-world outcome differs from the report the human read.

**This is within what was approved.** `on_conflict` exists precisely to define bounded,
acceptable behaviour under that divergence — an operator selecting `skip` has approved *"do not
overwrite what is there"*, which is a rule about whatever is there at the time, not a prediction
about a specific device. Any outcome the mode produces is inside the approval.

Freezing the target was considered and is not merely undesirable but unworkable here: the health
worker writes `reachable` and `last_check` for every device on every cycle, so a registry-wide
version stamp would be stale before a human finished reading the report. A restore that refused
on any concurrent registry change would refuse essentially always, and the pressure would then
be to disable the check.

So three distinct guarantees, which must not be conflated:

| Question | Answered by |
|---|---|
| Is this the operation that was reviewed? | The digest |
| Is the behaviour under divergence acceptable? | `on_conflict`, chosen by the operator |
| What actually happened? | The apply's own per-device report, audited |

The digest is not a promise about the world; it is a promise about the instruction.

##### The digest is an integrity commitment, not a capability — so it is not session-bound

The session-binding move that secures Tier 0's pending grant in
[ADR-0017](0017-provider-authority-is-delegated.md) §7 is deliberately **not** applied here, and
the reason is a difference in the objects rather than a preference:

| | ADR-0017's request id | This digest |
|---|---|---|
| Holding it gets you | A credential | Nothing |
| To use it you also need | Nothing | `backup:write`, the elevated grant, and the archive |
| What it is | A capability | A commitment to content |

Because holding a digest confers no access, protecting it like a capability would be pattern
matching on the mechanism instead of the property. It would also couple the two: a digest with
a session lifetime dies on a browser refresh, taking a reviewed plan with it, and the pressure
that creates lands on the session-death rule ADR-0017 §7 just made strict. Keeping them
separate keeps that rule unpressured.

##### Cross-session apply is permitted, and the digest is not what would make it safe

Whether one operator may preview and another apply is settled here so it is not discovered
later: **it is permitted, and it is not a reviewed-handoff feature.**

The deciding fact is that the gateway persists no plan. The archive travels in the request body
on the dry run and again on the apply, so a "handoff" means transferring the archive itself —
and anyone holding the archive plus `backup:write` can compose and submit any restore they
like, reviewed by nobody. The digest constrains *an* apply to match *a* preview; it establishes
nothing about who reviewed what.

So two-person review is **not** a property this provides, and it is **not wanted**. Requiring a
second human would need a server-side plan, an approver identity distinct from the submitter,
and a record binding them; the operational cost of that lands on every restore, including the
ones run at 3am by the only person available. Decided rather than deferred, so no later reading
of "preview then apply" mistakes it for an approval workflow.

**What is wanted is the audit trail, and the digest supplies it.** Both calls already record
their actor — `audit_request` stamps `subject_of(request)` and a request id — and both already
carry the `dry_run` flag, so *who* and *which kind* are captured today. What is missing is the
join: nothing connects a specific preview to the apply that followed it, and with no
server-side plan there is no object to correlate on.

The plan digest is that key, at no extra cost, so **both audit records carry it**:

| Record | Actor | `dry_run` | `plan_digest` |
|---|---|---|---|
| The preview | who previewed | `true` | the digest produced |
| The apply | who applied | `false` | the digest submitted |

"Who reviewed this exact plan, and who executed it" becomes a query on one field rather than an
inference from timestamps. A **refused** apply is audited the same way — a stale digest is a
denial worth having in the chain, not only in metrics — which also makes an apply that never
had a matching preview visible as an absence rather than invisible.

Note what this deliberately does not do: it **records** the two actors without **requiring**
them to differ. An operator who previews and applies alone produces a trail showing exactly
that, which is the honest record of what happened rather than a control pretending to be one.

##### A stale digest names the field and never the value

Because cross-session apply is permitted, the disclosure question is real rather than
dissolved, and it is narrow. The submitter already holds the entire request they are
submitting; what they do not hold is the previewer's value for a field that differs. So:

**A stale rejection names which fields diverged. It never returns the previewed value, nor the
previewed digest's inputs.**

That is the whole usability win — an operator is told exactly where to look instead of
re-deriving a whole request — with the one thing that could belong to somebody else's plan
withheld. And the residual is small on its own terms: whoever can submit an apply already holds
standing authority to run a fully destructive restore of their own choosing, audited
identically, so learning *that* `on_conflict` differed is not capability they lacked.

##### A stale digest has its own error code

`ERR_PLAN_STALE`, distinct from ordinary request validation, for the same reason §7 separates
`ERR_CREDENTIAL_UNRESOLVED` from `ERR_SECRET_STORE_UNAVAILABLE`: it is a signal in both of the
ways it can occur, and folding it into generic 400s makes both invisible.

- **Legitimate drift** — someone changed a field after previewing. The mechanism working, and
  worth a rate rather than a page.
- **A digest submitted from somewhere it should not be** — replayed, copied, or guessed against
  a request it never described. Rare, and worth knowing about immediately.

Those want different responses, so they must be distinguishable in monitoring rather than
inferred from a 400 count.

##### Consequence: the consumption record has no members left

With `backup:export-portable` removed, `backup:read` reduced to configuration, and
`backup:write` time-boxed, **nothing in the grant vocabulary is single-use.** The §11a
consumption machinery — the store protocol, both implementations, and `_consumption_id` —
becomes unreachable.

ADR-0017 supersedes §11a anyway, so this is a convergence rather than a conflict: 0018 reaches
the same deletion independently and earlier, which means it need not wait for 0017 to land.

What must not be deleted is the *reasoning*. `_consumption_id` records a lesson bought against
a real IdP — that keying on `jti` grants one spend per token refresh, and `auth_time` is the
only value that changes exactly when a new step-up happens. The code goes; that stays here and
in ADR-0013 §11a's record, because the next mechanism keyed to an authentication event will
face the same choice.

**This is the last moment to state it.** [ADR-0017](0017-provider-authority-is-delegated.md)
moves grant issuance to the tenant's IdP, at which point this taxonomy is what the tenant's
directory is asked to model. Carrying a category that names nothing into that conversation
would make the tenant's IdP configuration harder for no reason.

### 7. The secret store is its own failure domain, with its own state

> **Scope: this section describes the NETWORKED backends** — Vault, a cloud secret manager,
> §2's middle row. It was written as though it covered all three, and it does not. The
> mounted-files backends (§2 rows 1 and 3 — a Kubernetes Secret/CSI volume, and Lite's local
> file tree) have a different failure model, set out in §7a. Read §7a first if you are
> deploying either of those, which today is most deployments.

§2's first draft said a resolver failure is a device failure. That is right for one case and
badly wrong for the other, and the difference matters more than the similarity.

A device being offline fails **one** device. A sealed or partitioned secret store fails
**every** device at once, for a reason that is neither the device's fault nor the tenant's.
Folding the second into the first produces three distinct failures:

- Each device's breaker accumulates failures it did not cause, opens, and then has to recover
  from them. When the store comes back, the fleet stays down for as long as each device's reset
  timeout independently takes to elapse — a self-inflicted outage extending past the real one.
- The operator reads N devices going unreachable as a network event in the estate, and goes
  looking at the devices. The one thing that is actually broken is the one thing not named.
- The existing three breaker states — `closed`, `open`, `half-open` — describe *this device's
  upstream*. There is no honest way to express "the device is fine and we cannot call it" in
  that vocabulary.

#### Three resolution outcomes, not one

| Outcome | Scope | Nature | Handling |
|---|---|---|---|
| Resolved | — | — | Dispatch proceeds |
| **Reference invalid** — no such secret, denied, malformed | This device | Permanent; a misconfiguration | Mark the device faulted with a named reason. No retry, no breaker — retrying a typo is noise |
| **Store unavailable** — sealed, unreachable, timing out | Fleet-wide | Transient; nobody's mistake | Resolver-level breaker; devices untouched |

Collapsing those two is the same mistake one level down: one is a tenant's configuration error
that a retry cannot fix, the other is an infrastructure event that a retry is exactly right for.

#### The breaker belongs to the backend, not the device

There is **one circuit per resolver backend**, not one per device. When it is open, every
device resolving through it reports the *resolver's* state, and each device's own breaker is
left closed and untouched — so nothing has to recover from a fault it did not have. One probe
against the store re-admits the whole fleet at once, which is the correct granularity for a
shared dependency.

Diagnostics therefore gain a resolver block alongside `breaker`, and dispatch gains error codes
that do not collide with `ERR_CIRCUIT_OPEN`:

- `ERR_CREDENTIAL_UNRESOLVED` — this device's reference is bad. Yours to fix.
- `ERR_SECRET_STORE_UNAVAILABLE` — the store is down. Not this device, not this tenant.

Structured codes rather than a prose reason, because "silently looks identical to a device
being offline" is a *machine*-readability problem first: it is what decides whether an alert
fires on the store or on twenty devices.

#### The store joins Redis as a gateway dependency — but does not gate readiness

Dispatch now has a hard dependency the gateway's own uptime does not cover, which puts the
secret store in the same tier as Redis, and the fleet health endpoint must report it as a named
dependency rather than leaving it to be inferred from device symptoms.

**Readiness deliberately does not fail when the store is down.** Pulling the pod out of service
would remove the console, diagnostics and every read — the operator would lose the ability to
see *why* the fleet stopped, at the moment they need it. A gateway with an unreachable store is
degraded, not dead: everything except dispatch still works. It reports degraded, it alerts, and
it stays up.

This also upgrades the resolution cache from a performance decision to an availability one: a
short TTL is what makes a brief store blip invisible. It must still never become a durable
copy — that line is §1 — but the TTL is now trading three things against each other, not two.

**The cache is instrumented from the first deployment, not when tuning begins.** Hit rate, miss
rate, resolution latency against the store, and entry age at the moment of use ship with the
resolver rather than being added later. The TTL cannot be reasoned to from first principles, so
the only question is whether the data to choose it accumulates naturally in production or has to
be manufactured by a dedicated load test that will approximate the wrong workload. Building the
measurement in costs four metrics; leaving it out converts a tuning decision into a project.

### 7a. The mounted-files backend is a deploy-time dependency, not a dispatch-time one

§7's scenario — a store that vanishes underneath a running process, a fleet-wide breaker,
`StoreUnavailable` surfacing at dispatch — is a real description of a networked store. For a
Kubernetes Secret or CSI volume, and for Lite's local file tree, **it does not occur**, and
designing for it there produces machinery that cannot be exercised.

Established by measurement on a live cluster (2026-08-19), not by reasoning:

| Event | What actually happens |
|---|---|
| Secret **deleted** while pods run | Nothing, from the pod's side. The volume keeps its last projected content indefinitely — the kubelet has no source to re-project from. Dispatch keeps succeeding |
| Secret **modified** (key renamed, value changed) | Re-projected in ~30–60s. This is the *only* way a running pod sees a credential change |
| Pod **restarts** while the Secret is absent | `FailedMount`; the pod sticks in `ContainerCreating` and never becomes Ready. The old pods, still running, keep serving |
| Node/kubelet cannot reach the API server | The mount is already materialised on local disk; reads do not consult the API server |

The store is therefore a dependency of **starting a pod**, not of **serving a request**. Its
failure mode is a deployment that will not roll — loud, visible in `kubectl get pods`, and
caught by exactly the readiness machinery that already exists — rather than a fleet of healthy
pods that suddenly cannot authenticate.

Three consequences for what gets built:

1. **No fleet-wide breaker for this backend.** There is no transient shared outage for it to
   ride out. A resolution failure here is `ReferenceInvalid` — a missing file, a wrong key
   name, a mode the check refuses — and every one of those is permanent and scoped to one
   device, which is §7's *first* row, not its second. `StoreUnavailable` remains reachable for
   one cause only: the mount itself is unreadable (wrong ownership, wrong `fsGroup`), which is
   genuinely fleet-wide and genuinely the operator's to fix.
2. **The resolution cache buys nothing here.** §7 upgrades the cache from a performance
   decision to an availability one, on the reasoning that a short TTL makes a store blip
   invisible. A local file read has no blip to hide and costs microseconds. The cache and its
   four metrics belong with the networked backend that motivates them; adding them now would
   mean shipping an unbounded in-memory copy of every credential — the thing §1 exists to
   prevent — in exchange for nothing.
3. **What a mounted-files deployment actually needs to monitor** is the credential *file set*:
   a reference naming a file that is not there, and a mount whose ownership the resolver
   refuses. Both are configuration errors that surface at the first resolution, and neither is
   improved by a breaker.

**The warm-path corollary, which cost a defect to learn.** Because the mount survives its
Secret and only re-projects on modification, the realistic credential outage on this backend is
not "the store went away" but "a live device's credential changed underneath it" — a rotation
that removed the old key, an operator editing the wrong entry. That device is *already running*
and already assigned, so nothing in the spawn path will ever look at it again. Whatever records
the reason has to live in the **health loop**, not only in spawn. Finding #11 was exactly this,
and §7's dispatch-time framing is part of why it was not anticipated.

### 7b. Upgrade order is a constraint, not a preference

Measured on a live cluster (2026-08-19) by running a pre-wiring worker image against migrated
devices. A replica that predates the resolver wiring **fails closed** — `ApiKeyAuth._value`
raises before a header is built, so nothing bogus is sent upstream — but it records **no reason
on the device record**. The device shows `reachable: false` with an empty `spawn_error`, and
the cause exists only in that worker's log.

The mechanism is worth stating because it is not obvious: the un-wired worker *successfully
spawns* the pod, because a cached manifest needs no credential. Only the subsequent health check
fails, and the reason channel a health check needs did not exist before this slice. So the
window is **dark rather than wrong** — which is worse for an operator than a loud failure.

It cannot be fixed in an already-released image, so it is closed by sequencing instead:

> **Upgrade workers first, then the gateway, and only then migrate any device to a reference.**

A device becomes by-reference through a gateway API call. If the workers are wired before that
call is possible, no by-reference device is ever assigned to an un-wired worker and the window
never opens. Rolling the gateway first opens it for the length of the worker rollout.

### 7c. The cache, the breaker and their metrics are backend-conditional

§7a established that the mounted-files backend fails at **deploy time** rather than dispatch
time. That finding does not stop at the cache: it invalidates a premise under **three** pieces
of §7's machinery, and all three are named here rather than discovered one at a time during
implementation. None of them is built yet, so this costs nothing to adopt.

**The rule, stated once:** §7's dispatch-time machinery is **on for networked backends and inert
for mounted-files ones**. It is scoped, not deleted — the networked backends are precisely why it
exists.

#### The cache: on for networked, TTL 0 and read-through for mounted files

§7 promotes the cache from a performance decision to an availability one, trading against two
things: hot-path latency, and tolerance of a brief store outage. **For mounted files both axes
are moot.** A local file read has no network round-trip to amortise, and §7a's measurements show
availability does not degrade transiently — the volume is mounted before the pod is ready, or the
pod never becomes ready at all. There is no blip to hide and no latency to spend.

What does not go away is the cache's **cost**: a resolved plaintext credential held in process
memory for as long as the TTL. That is not "at rest" on disk, but it is the same *shape* as the
durable copy §1 exists to prevent, and §1's line is worth more than a saving that is structurally
zero. So on a mounted-files backend the cache is **TTL 0, read-through** — resolution reads the
file every time, which is what the implementation already does today and should keep doing.

#### The breaker: keep it, but do not pretend it is uniformly exercised

`StoreUnavailable`, the per-backend circuit and its backoff describe a **dispatch-time**
fleet-wide failure. §7a establishes that a mounted-files store does not fail at dispatch time, so
for that backend **there is no state the breaker can meaningfully trip on.** The one residual
fleet-wide fault — a mount whose ownership the resolver refuses — is present from the first
resolution and is not transient, so a circuit that opens and later probes for recovery is the
wrong instrument for it too.

The breaker is **not wrong to keep**; it is the correct design for the backends it was written
for, and `credentials/resolver.py` already says so — the networked backends "arrive with the
circuit breaker of §7, which they are the reason for."

**The risk this section exists to head off is a test suite that appears to cover the breaker and
does not.** On a mounted-files deployment the breaker path is unreachable, so tests exercising it
can only do so against a fabricated resolver — and a test that proves a policy against an
in-repo double proves nothing about the production implementation. That mistake has already been
made in this project once. The breaker's tests must be written against a **networked** resolver
when one exists, and until then its coverage should be honestly recorded as absent rather than
simulated. This is the same treatment verification rows C1–C3 received: restated against the real
failure mode, not deleted and not faked.

#### The metrics inherit the scoping

Hit rate, miss rate, resolution latency and entry age at use are only meaningful where there is a
cache and a store to be latent. Shipping them as blanket resolver-wide instrumentation would emit
series that are **structurally zero or undefined** on every mounted-files deployment — which is
every Lite and embedded install, and the default Kubernetes path.

So the instrumentation, its dashboards and its alerts are **scoped by backend kind from the
start**, not filtered afterwards when someone notices a Lite deployment reporting a 0% cache hit
rate and opens an incident about it. A panel that is empty because the mechanism does not apply
is indistinguishable, at a glance, from one that is empty because the mechanism is broken.

#### This needs a first-class backend kind, not string matching

Three behaviours now branch on which backend is in use, so the discriminator becomes load-bearing.
`CredentialResolver` today exposes only `backend: str` (`"files:/run/secrets/mcp"`), and
conditioning on `backend.startswith("files:")` would put a policy decision behind a string prefix
— the kind of implicit contract that breaks quietly when a fourth backend is added.

The resolver protocol should carry the distinction explicitly — a `kind` discriminator, or a
capability flag such as "resolution can fail transiently at dispatch" — so the cache, the breaker
and the metrics all read the same declared property rather than three call sites each inferring
it. The name is an implementation choice; that it is declared rather than inferred is not.

## Consequences

- **Positive: an exported archive stops being a credential.** It can be stored in Git,
  reviewed in a pull request, diffed between environments, and handed to a customer.
- **Positive: `MCP_SECRET_KEY` stops being the crown jewel for an entirely
  operator-provisioned fleet**, and with it the awkwardness of the provider holding it. It
  remains exactly as load-bearing as before for any deployment with an OAuth2 refresh-token
  device (§1a) — for those, this ADR changes nothing about what a key compromise costs.
- **Positive: credential rotation stops involving the gateway.** Rotate in the store; the next
  dispatch picks it up.
- **Positive: the elevated-grant taxonomy loses a tier** and the axis that remains — blast
  radius — is the one that was doing the work all along (§6). One fewer concept to model in a
  tenant's IdP under ADR-0017.
- **Positive: single-use leaves the vocabulary entirely**, taking the consumption store and its
  Redis dependency with it (§6). The iterative dry-run loop ADR-0011 designed for becomes
  reachable, which it currently is not.
- **Negative: the plan digest is new machinery on the restore path** — produced by dry run,
  carried by apply, validated server-side. It replaces a bound that was one boolean.
- **Negative: a dispatch depends on a secret store being reachable — on networked backends**,
  and that dependency is fleet-wide where the previous one was per-device. Mitigated by
  short-lived in-process caching with an explicit TTL — a **performance** decision that must not
  become a durable copy, which is exactly the line this ADR draws. **On a mounted-files backend
  this cost does not arise at all** (§7a): the dependency is at pod start, and the cache is
  therefore TTL 0 (§7c).
- **Negative: the health model grows a dependency and two error codes** (§7). This is net-new
  surface in diagnostics, the fleet health endpoint and alerting — and it is not optional, since
  the whole point is that a store outage must not be legible only as twenty device outages.
- **Negative: three behaviours now branch on backend kind** (§7c) — the cache, the resolver
  breaker, and the cache metrics. That is a real increase in conditional surface, and it is
  accepted because the alternative is worse in a specific way: uniform machinery whose
  dispatch-time paths **cannot be reached** on the backend most deployments use, carrying tests
  that appear to cover them and metrics that are structurally zero. The branch is made explicit,
  on a declared property of the resolver rather than inferred from its name.
- **Negative: the rollout has an order that cannot be reversed** (§7b). Gateway-first leaves a
  window in which a migrated device assigned to an un-wired worker reports a bare failure with
  no cause. Fails closed, so it is not a security exposure — but it is an observability one, and
  it is invisible unless the runbook says so.
- **Negative: a `grant_type=refresh_token` device does not survive a restore unaided** (§3). Its
  token is excluded from the archive and nothing else can re-mint it, so it arrives needing
  re-authorization. `client_credentials` and `password` devices are unaffected — their
  operator-provisioned secret survives and the exchange re-runs on first use. The cost is real
  but bounded, and it buys the retirement of the passphrase/KDF/envelope/canary path for every
  stack rather than only for entirely-operator-provisioned ones.
- **Negative: registration gets a step.** Someone must put the secret in the store before
  registering the device. The console can drive this where the backend supports writes, but
  the general case is a two-system operation and will be felt.
- **Negative: a restore into a fresh stack no longer carries everything needed to run.** This
  reads as a regression and is the honest form of a property the old design only appeared to
  have: the credentials were always the tenant's, and an archive that carried them was a copy
  of them.
- **The disaster-recovery story changes and must be re-tested.** The existing DR bed proved a
  rebuild from an archive; it now proves a rebuild from an archive *plus* a secret store, which
  is a different exercise and a more realistic one.

## Alternatives considered

**Envelope encryption with a per-tenant KEK in a KMS.** Keeps credentials in the registry but
makes the provider unable to decrypt without a per-tenant key they can be denied. Rejected as
a half-measure: the ciphertext is still in the archive, the two archive kinds still exist, the
shred still has to chase copies, and the gateway still handles plaintext at rest in memory
management terms. It buys the hardest property (provider cannot read) at most of the cost of
the current design.

**Keep credentials at rest but exclude them from backups.** Simple and removes the credential
dump. Rejected because it makes restore silently incomplete, which is worse than making it
visibly dependent — a restored stack that comes up with every device unreachable and no
explanation is the failure mode this project has already shipped once.

**Short-lived credentials brokered per dispatch (OAuth client credentials, workload identity
federation to the device).** The right long-term answer where the device supports it, and this
ADR does not preclude it — a resolver can mint as easily as it can fetch. Not made mandatory
because most devices in the target fleet are appliances with static API keys, and a design that
required otherwise would not describe the actual estate.

## Open questions

- ~~**The reference format.**~~ **Resolved** (implemented in #129/#130): backend-neutral
  `secret://`, in the direction this leaned. Naming the backend would bake a deployment choice
  into every device record, so an archive could only be restored into a stack running the same
  product — which is precisely the portability §3 is built on.
- **The TTL value itself — for networked backends only** (§7c; on mounted files the TTL is 0 and
  the question does not arise). §7 settles that the cache ships instrumented; the number comes
  from the resulting data, and the three-way trade (rotation, hot path, outage tolerance) means
  there may be no single right answer across deployment sizes.
- **Whether a store outage should fail open on cached material past its TTL — networked backends
  only** (§7c; a mounted-files store has no dispatch-time outage for this to arise from). Serving
  a stale credential to keep the fleet dispatching is the availability answer; refusing is the
  correctness one. Leaning refuse, since a rotated-away credential failing at the device is a
  worse diagnosis than an honest `ERR_SECRET_STORE_UNAVAILABLE`.
- **How long a plan digest stays valid.** §6 gives it no expiry of its own beyond the grant
  window that gates the apply. A digest previewed weeks ago and applied inside a fresh grant
  would still match if nothing in the request changed, which is arguably correct — the
  instruction is unaltered — and arguably too long for "reviewed".
- **Whether the console should write to the secret store** where the backend allows it, or
  refuse on principle and keep registration a two-system operation.
