# ADR-0019: The tenant identifier is opaque from birth

- **Status:** Proposed
- **Date:** 2026-08-17
- **Supersedes:** [ADR-0014](0014-tenant-namespace-naming-and-network-isolation.md) §1.
  ADR-0014 §2–§8 stand unchanged.

## Context

ADR-0014 §1 names tenant namespaces `mcp-t-<pseudonym>`, where the pseudonym is a truncated
keyed HMAC over the tenant identifier. The reasoning is sound and worth restating, because
this ADR keeps the goal and changes only how it is reached:

> A namespace called `mcp-acme-corp` writes that customer's name into every `kubectl` output,
> every Prometheus label, and every alert, log line and dashboard derived from them — and a
> namespace name is not encrypted, so it survives the crypto-shred that ADR-0013 §10 exists to
> provide.

Entirely correct. But look at what the fix costs: a key (`K_ns`) to generate, distribute and
protect; a domain-separation rule to remember; a standing warning never to reuse that key
material for the audit pseudonym; a collision assertion at provisioning time because 64
truncated bits make collision improbable rather than impossible; and a tombstone so a reissued
tenant identifier cannot recompute a departed tenant's namespace.

All of that exists to hide a value we chose to make revealing.

## Decision

### 1. Tenant identifiers are opaque, and are not derived from anything

A tenant is assigned an opaque, stable identifier at creation:

```
t-7f3a91c4
```

It is random, not derived. It carries no customer information, so nothing needs to hide it,
and it is the identifier used **everywhere** — namespace names, metric labels, audit records,
credential references, archive contents, configuration, support tickets.

The namespace becomes `mcp-t-7f3a91c4`, or simply the identifier itself where the platform
allows.

**The separator is a hyphen, and that is not cosmetic.** `t_7f3a91c4` — the natural way to
write a prefixed identifier — is not a valid DNS-1123 label, so it can be neither a Kubernetes
namespace name nor a hostname label. §2 puts this identifier in both: the namespace here, and
the per-tenant console hostname in [ADR-0021](0021-separate-console-applications.md) §5, where
an underscore would additionally be refused a certificate by any public CA. An identifier that
is valid everywhere it appears is worth more than one that reads slightly better in prose.

Keeping the `mcp-t-` namespace prefix is a happy side effect: existing manifests, labels and
Cilium selectors keep their shape, and only the way the suffix is produced changes.

### 2. Exactly one mapping exists, and it lives outside the cluster

A single provider-side record maps customer to tenant identifier. It is the only place the
customer's name and their identifier appear together, it is not deployed to any cluster, and
it is not readable from a tenant's stack.

**Random rather than derived is the whole decision**, and it is worth being explicit about why,
because "hash the name" is the reflex:

- A derived identifier is reversible by dictionary attack over a plausible customer list —
  ADR-0014 §1 says exactly this about bare hashes, which is why it reached for a keyed HMAC.
  Random is not reversible by any attack, because there is nothing to reverse.
- A derived identifier requires the key at every point that needs to compute it — provisioning,
  restore, rebuild, and any tool that maps between the two. Random requires a lookup, and the
  lookup is a table the provider already needs for billing and support.
- Determinism was the argument for deriving: GitOps, a rebuild and an ADR-0011 restore can all
  recompute the namespace without a stateful allocation record. But **the identifier is itself
  the durable record**, stored in the same declarative source those three read from. Nothing
  needs recomputing when nothing was computed.

### 3. What this removes

- `K_ns`, its generation, distribution, rotation and protection.
- The domain-separation construction and the rule about not reusing key material.
- The collision assertion at provisioning time — random identifiers of adequate width collide
  no more often, but more importantly there is no truncation of a derived value to reason
  about.
- The `tools/tenant_namespace.py` derivation helper and its tests.

### 4. What this keeps, unchanged

- **The tombstone.** An identifier is never reissued, for exactly the reason ADR-0013 §10 and
  ADR-0014 §1 both give: stale DNS, cached tokens and bookmarked consoles from a departed
  tenant must never resolve onto a new one. Randomness makes accidental reuse unlikely;
  the tombstone makes deliberate reuse impossible, and those are different guarantees.
- **Every other part of ADR-0014.** Label-based policy selection, default-deny in both
  directions, the named Prometheus exception, the RBAC/CNI reasoning, the absence of an
  inter-tenant exception mechanism, and the Tier 1 / Tier 2 conclusion are untouched. This ADR
  changes what goes in the name, not what the boundary does.
- **The audit pseudonymizer.** It solves a different problem — stable handles for provider
  *principals* in a tenant's audit — and keeps its key.

## Consequences

- **Positive: one fewer key in the system**, and the removal of a rule ("never reuse this key
  material") that had to be remembered rather than enforced.
- **Positive: identifiers are readable in the sense that matters** — an operator can say
  `t-7f3a91c4` aloud, put it in a ticket and paste it into a dashboard without disclosing a
  customer.
- **Negative: humans cannot tell which customer a namespace belongs to without a lookup.**
  This is the intent, and it is also a genuine day-to-day operational cost during incidents.
  The provider's tooling should resolve identifiers to names in *provider-side* interfaces —
  never by putting the name back into the cluster.
- **Negative: the mapping record becomes operationally critical.** Losing it does not lose
  data, but it loses the ability to say whose data it is. It needs the same care as any other
  business record, which is a different discipline from key management but is not less.
- **Migration for an existing estate is a rename**, which for a namespace means recreate. Not
  a problem today with one lab tenant; it would be a real project with fifty.

## Alternatives considered

**Keep the keyed HMAC.** It works and is already specified. Rejected because it is machinery
to conceal a value that need not be revealing — and because the key it introduces sits
uncomfortably close to the audit pseudonym key, with only a documented rule keeping them
apart.

**A UUID.** Fine, and functionally equivalent. A short prefixed identifier is preferred purely
because it appears in namespace names, metric labels and conversation, where 36 characters of
hyphenated hex is a cost paid many times a day for entropy nobody needs.

**Sequential identifiers (`t_0001`).** Rejected: they leak customer count and ordering, which
is commercially sensitive in a way a customer's name is not, and they invite enumeration.

## Open questions

- **Width and format.** 32 bits of randomness is enough to avoid accidental collision at any
  plausible estate size, but not enough to resist enumeration if identifiers are ever exposed
  to a party who should not enumerate them. Whether that matters depends on where identifiers
  appear, which §2 has deliberately made broad.
- **Whether the tenant should ever see their own identifier.** They must, for support; the
  question is whether it appears in their console by default or only when asked for.
