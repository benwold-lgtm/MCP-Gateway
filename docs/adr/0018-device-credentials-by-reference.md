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
credential_ref: "vault://t_7f3a91c4/devices/prism#api-key"
```

The gateway resolves the reference at dispatch time and does not persist the result beyond the
request. It never holds a decryptable copy of any device credential at rest.

**The secret store belongs to the tenant, not to the provider.** This is what makes the change
a security improvement rather than a relocation: a provider who cannot read the store cannot
read the credentials, whatever they hold in the gateway.

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

### 4. Offboarding is a secret-store operation

ADR-0013 §10 buys erasure by destroying a per-tenant content key so that hashes survive and
content does not. For *audit* content that remains exactly right and is untouched here.

For *credentials* it stops being the gateway's problem. Deleting the tenant's namespace in the
secret store revokes every device credential at once, whatever archives exist and wherever
they are. The archive-retention hole — a backup expiring on its own schedule, outliving the
shred — closes because there is nothing in the archive to outlive.

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
| Single-use semantics for `backup:write` (restore) | **Survives**, on destructiveness rather than disclosure — §6 |

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

The tempting conclusion is that single-use goes with it, and that would be wrong. Look at what
was actually in the class: `backup:read` and `backup:export-portable` — credential-bearing —
but also **`backup:write`**, which is restore.

Restore was single-use because it travelled in the credential class. It has an independent
reason to be, and that reason survives §3 untouched: **restore overwrites a tenant's device
registry.** Its risk is destructiveness, not disclosure. The single-use grant and the §11d
consumption record are the right shape for "one operation, then re-authenticate" regardless of
whether a secret was involved.

So the elevated taxonomy loses a tier and gains a clearer axis. It was implicitly
**credential-bearing vs not**; it becomes **blast radius**:

| | Grant | Duration | Why |
|---|---|---|---|
| Acts on one device, reversibly | `provider:invoke` | Time-boxed | ADR-0013 §5, unchanged |
| Overwrites the registry | `backup:write` | **Single use** | Destructive, not credential-bearing |
| Reads configuration | `devices:read` / `backup:read` | Ordinary | Nothing elevated remains |

That axis is the better one. It explains why restore is gated without appealing to a fact
about restore that is no longer true, and it does not need a grant category to hold a single
member.

**This is the last moment to state it.** [ADR-0017](0017-provider-authority-is-delegated.md)
moves grant issuance to the tenant's IdP, at which point this taxonomy is what the tenant's
directory is asked to model. Carrying a category that names nothing into that conversation
would make the tenant's IdP configuration harder for no reason.

### 7. The secret store is its own failure domain, with its own state

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

## Consequences

- **Positive: an exported archive stops being a credential.** It can be stored in Git,
  reviewed in a pull request, diffed between environments, and handed to a customer.
- **Positive: `MCP_SECRET_KEY` stops being the crown jewel**, and with it the awkwardness of
  the provider holding it.
- **Positive: credential rotation stops involving the gateway.** Rotate in the store; the next
  dispatch picks it up.
- **Positive: the elevated-grant taxonomy loses a tier** and the axis that remains — blast
  radius — is the one that was doing the work all along (§6). One fewer concept to model in a
  tenant's IdP under ADR-0017.
- **Negative: a dispatch now depends on a secret store being reachable**, and that dependency is
  fleet-wide where the previous one was per-device. Mitigated by short-lived in-process caching
  with an explicit TTL — and the cache is a **performance** decision that must not become a
  durable copy, which is exactly the line this ADR draws.
- **Negative: the health model grows a dependency and two error codes** (§7). This is net-new
  surface in diagnostics, the fleet health endpoint and alerting — and it is not optional, since
  the whole point is that a store outage must not be legible only as twenty device outages.
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

- **The reference format.** A URI is the obvious shape, but whether the scheme names the
  backend (`vault://`) or is backend-neutral (`secret://`) with resolution configured per
  deployment changes how portable an archive is between stacks. Leaning backend-neutral.
- **Cache TTL now trades three ways, not two** — a long cache defeats rotation, a short one
  puts the store in the hot path, and the cache is also what rides out a brief store outage
  (§7). Needs measurement against a real store, not a guess.
- **Whether a store outage should fail open on cached material past its TTL.** Serving a stale
  credential to keep the fleet dispatching is the availability answer; refusing is the
  correctness one. Leaning refuse, since a rotated-away credential failing at the device is a
  worse diagnosis than an honest `ERR_SECRET_STORE_UNAVAILABLE`.
- **Whether restore stays single-use once ADR-0017 lands.** §6 says its justification survives;
  whether a tenant's own IdP should be asked to model a single-use grant for an operation the
  tenant is performing on their own stack is a different question, and belongs to ADR-0017.
- **Whether the console should write to the secret store** where the backend allows it, or
  refuse on principle and keep registration a two-system operation.
