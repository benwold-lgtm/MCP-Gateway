# ADR-0018: Device credentials are held by reference, never at rest in the gateway

- **Status:** Proposed
- **Date:** 2026-08-17
- **Supersedes:** most of [ADR-0011](0011-backup-and-restore.md) — see §5.
  Affects [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) §5b and §10.

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

**A resolver failure is a device failure, not a gateway failure.** An unresolvable reference
marks that device unreachable with a named reason and leaves the rest of the fleet running,
for the same reason a device whose upstream is down does not take the gateway with it.

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
| `backup:export-portable` scope, `provider:credentials` grant | Removed |

## Consequences

- **Positive: an exported archive stops being a credential.** It can be stored in Git,
  reviewed in a pull request, diffed between environments, and handed to a customer.
- **Positive: `MCP_SECRET_KEY` stops being the crown jewel**, and with it the awkwardness of
  the provider holding it.
- **Positive: credential rotation stops involving the gateway.** Rotate in the store; the next
  dispatch picks it up.
- **Negative: a dispatch now depends on a secret store being reachable.** Mitigated by
  short-lived in-process caching with an explicit TTL — and the cache is a **performance**
  decision that must not become a durable copy, which is exactly the line this ADR draws.
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
- **Cache TTL and its interaction with rotation.** A long cache defeats rotation; a short one
  puts the store in the hot path. Needs measurement against a real store, not a guess.
- **Whether the console should write to the secret store** where the backend allows it, or
  refuse on principle and keep registration a two-system operation.
