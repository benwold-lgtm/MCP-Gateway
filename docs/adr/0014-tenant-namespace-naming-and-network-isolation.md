# ADR-0014: Tenant namespace naming, and default-deny network isolation between tenants

- **Status:** Proposed (implemented — see *Implementation notes*)
- **Date:** 2026-08-12
- **Related findings:** F-68 (NetworkPolicies are peer-blind — *not yet filed*, see Context),
  F-01 (no in-app tenant isolation), F-02 (SSRF / wide NetworkPolicy egress),
  F-33 (cross-API isolation is process-shared), F-36 (metrics exposition unauthenticated)
- **Builds on:** [ADR-0004](0004-single-tenant-per-stack.md) (one stack per tenant),
  [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) (two-plane tenancy; §7
  monitoring path, §9 tenant visibility, §10 offboarding)
- **Scope:** Kubernetes deployments. See §7 for the Compose/Lite analogue.

## Context

[ADR-0004](0004-single-tenant-per-stack.md) makes tenancy a **deployment boundary**, and
[ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) builds a provider plane on top
of that boundary being real. [multitenancy.md](../multitenancy.md) already states the
requirement — *"Its own network boundary / namespace. In Kubernetes, a namespace per tenant
with NetworkPolicies"* — and ADR-0013's own Context lists "its own egress policy and
NetworkPolicy" among the properties a stack-per-tenant buys.

Nothing implements it.

**The namespace is hardcoded.** `deploy/kubernetes/namespace.yaml` names `mcp-gateway`, and
`kustomization.yaml` pins `namespace: mcp-gateway`. Two tenant stacks deployed from these
manifests land in the *same* namespace and collide — sharing a Redis, a ConfigMap and a
Service, which is precisely the co-hosting ADR-0004 forbids as its load-bearing rule.

**The NetworkPolicies are peer-blind, and this is worse than having none.** Every ingress
rule in `networkpolicy.yaml` specifies `ports:` with **no `from:`**, and every egress rule
specifies `ports:` with no `to:`. In NetworkPolicy semantics that reads "any peer in the
cluster, on these ports." `kubernetes-architecture.md` summarizes the result accurately as
*"Restricts ingress to port 8000"* — which is the trap in one line. It restricts **ports,
not peers**, and a reader checking whether network isolation exists sees a file called
`networkpolicy.yaml` and a doc row saying "Restricts ingress" and concludes that it does.

Measured rather than inferred, on the `mcp-gw` cluster (2026-08-12): a throwaway pod created
in an unrelated namespace reached `device-mcp-gateway.<ns>.svc.cluster.local:8000/health`
and received `HTTP 200` with the full health payload — version, mode, device count, live
workers. Cross-namespace routing into a tenant stack is open today.

Two structural points that shape the fix:

- **NetworkPolicy is pod-selected, and unselected pods are default-allow.** The three
  existing policies select only `app: device-mcp-gateway`, `app: device-mcp-worker` and
  `app: redis`. *Any other pod* in the namespace — a sidecar, a debug container, a tenant's
  own workload, anything an attacker lands — is selected by no policy at all and therefore
  has unrestricted ingress and egress in both directions.
- **Isolation between tenants currently rests entirely on the API key.** The in-app egress
  guard (`validate_target_url`, F-02/F-67) is what actually prevents a gateway from reaching
  a neighbour, not the network. That is a single layer where the architecture claims two.

This is a finding as well as a decision. It should be filed as **F-68** and given a
**TG-10** entry, because it is exactly the class of defect the unit suite cannot see: it was
found by one probe on a live cluster, and no amount of manifest review had caught it.

## Decision

A tenant namespace is **deterministically named from a pseudonym, labelled for policy
selection, and default-deny in both directions**. Cross-tenant reachability is denied
absolutely: there is no exception mechanism, and no supported way for the provider to open a
path between two tenants (§6).

### 1. The namespace name is a pseudonym, never the tenant's identity

Tenant namespaces are named:

```
mcp-t-<pseudonym>          e.g. mcp-t-9f4c1ab7d0e35286
```

where `<pseudonym>` is a truncated keyed HMAC-SHA256 over the tenant identifier. Six
characters of prefix plus sixteen hex characters is 22 — comfortably inside the 63-character
DNS-1123 label limit, with room for suffixed sibling namespaces if any are ever needed.

**The name must not carry the customer's identity, and this is not a style preference.**
ADR-0013 §10 buys erasure by destroying a per-tenant content key: the hashes survive, the
content does not. A namespace called `mcp-acme-corp` writes that customer's name into every
`kubectl` output, every Prometheus label and every alert, log line and dashboard derived from
them — and **a namespace name is not encrypted, so it survives the crypto-shred intact**. The
mechanism §10 exists to provide would be defeated by the deployment convention sitting
underneath it. This is the same reasoning that gave hostnames a tombstone rather than a
delete.

**Keyed, not a bare hash.** A bare hash of a tenant identifier is reversible by dictionary
attack over a plausible customer list, exactly as [ADR-0013 §9](0013-two-plane-tenancy-and-the-provider-plane.md)
argued for actor handles, which would make the pseudonym decorative.

**Reuse the construction, not the key.** The BFF already computes stable keyed handles in
`Pseudonymizer.handle()`. Reuse that *construction*; do **not** reuse the same key material
for both purposes, and domain-separate the input:

```
namespace_pseudonym = HMAC-SHA256(K_ns, "namespace:v1:" || tenant_id)[:8].hex()
```

The two pseudonyms have different exposure — an audit handle is read by that tenant, a
namespace name is visible to anyone with cluster read across the whole estate — and a shared
key would let one be used to probe the other.

**Deterministic, and asserted anyway.** Determinism is what lets GitOps, a rebuild, and an
[ADR-0011](0011-backup-and-restore.md) restore all recompute the same namespace from the
tenant identifier without a stateful allocation record. But 64 truncated bits make collision
*improbable*, not impossible, and the failure mode of a collision is two tenants sharing a
namespace — the single worst outcome in this architecture. **Provisioning asserts the
namespace does not already exist and fails closed if it does.** A negligible probability is
not a measurement; the assertion is.

**The pseudonym is tombstoned at offboarding**, alongside the per-tenant hostname of
ADR-0013 §10. Because the name is derived deterministically, reissuing a tenant identifier
would recompute a departed tenant's namespace and resurrect their name in every metric and
dashboard that retained it.

### 2. Policy selects on labels; the name is for humans

A naming convention cannot be enforced by NetworkPolicy — **NetworkPolicy selects on
labels**, and a name prefix is not a selector. Every tenant namespace therefore carries:

```yaml
metadata:
  name: mcp-t-<pseudonym>
  labels:
    mcp.gateway/plane: tenant
    mcp.gateway/tenant: <pseudonym>
```

Kubernetes additionally applies `kubernetes.io/metadata.name` to every namespace
automatically (GA since 1.21), which gives the "same namespace only" allow a reliable
selector that cannot be forged by omitting a label at creation time.

**Namespace labels are provider-writable only.** A namespace that can relabel itself can
either escape a deny keyed on `mcp.gateway/plane: tenant`, or attract traffic by claiming to
be a tenant it is not. Namespace `create`, `patch` and `label` are provider-plane RBAC
verbs; no tenant-plane credential holds them.

### 3. Default-deny both directions, then narrow allows

Each tenant namespace gets a policy selecting **all** pods — `podSelector: {}` with
`policyTypes: [Ingress, Egress]` and no rules — closing the gap in §Context where anything
that is not the gateway, worker or Redis is unpoliced. Reachability is then re-opened
deliberately, and only for:

| Direction | Peer | Why |
|---|---|---|
| Intra-namespace | Same namespace, both ways | The stack must talk to itself: gateway ↔ Redis, worker ↔ Redis |
| Egress | `kube-system` DNS, 53/UDP+TCP | Without this **everything** breaks, in a way that reads as an application bug |
| Ingress | Monitoring namespace → 9100 | ADR-0013 §7 — see §4 below |
| Ingress | Ingress-controller namespace → 8000 | The only legitimate route to the tenant API |
| Egress | Device CIDRs / ports | The existing allowlist, now with a `to:` as well as a `ports:` |

Cross-tenant denial is then a **consequence** of the default rather than a rule anyone
maintains. There is no `deny tenant B` clause to forget to update when tenant C arrives.

The existing per-workload policies keep their value and are not replaced: they remain the
narrower statement of what the gateway and worker specifically may reach, and the file's
existing warning — that a device on an unlisted port is simply unreachable, with a timeout
as the only symptom — applies with more force once the namespace default is deny.

### 4. The Prometheus scrape is a deliberate, named exception

ADR-0013 §7 rests on cross-tenant fleet health being aggregated from the **metrics plane**,
specifically so that `provider:monitor` — the constant-use read path — holds no tenant API
credential. That aggregation is a cross-namespace scrape by definition.

So a naive reading of "prevent routing between tenant namespaces" would break the provider
console's entire read path. The monitoring namespace is an explicit allowed peer on 9100 and
nothing else, in one direction, and it is the *only* standing cross-namespace path in the
design. `networkpolicy.yaml` already advises scoping 9100 with a `namespaceSelector` "in
production rather than leaving it open to the whole cluster"; this makes that mandatory
rather than advisory.

Note the direction of the exception: monitoring reaches **in** to tenants. No tenant
namespace is granted egress to another tenant namespace by any part of this decision.

### 5. A deny that cannot be undone is an RBAC or CNI property — not a NetworkPolicy one

This is the constraint that shapes the rest of the decision, and it is easy to get wrong.
§6 removes any *sanctioned* way to open a cross-tenant path; this section is about the
**unsanctioned** ones.

**Kubernetes NetworkPolicy is purely additive-allow. There is no way to write a policy that
revokes an allow granted by another policy.** The effective rule is the union of every
policy selecting a pod. Consequently, anyone who can create a NetworkPolicy inside a tenant
namespace can re-open cross-tenant reachability, and *no* provider-authored vanilla policy
anywhere in the cluster can prevent it. Deleting the default-deny is not even necessary — a
permissive policy added alongside it is enough.

So the boundary holding against a tenant who acquires namespace-write is not something the
default-deny provides by itself. It has to come from one of two places, and we adopt both as
tiers:

**Tier 1 — baseline, portable, required.** Tenant-plane credentials hold no `create`,
`patch` or `delete` on `networkpolicies` in any tenant namespace; GitOps is the sole writer.
This is honest about what it is: **an RBAC guarantee, not a network guarantee.** Anyone who
obtains namespace-write in a tenant namespace has also obtained the ability to undo the
boundary.

**Tier 2 — hardened, optional, recommended for any provider-operated estate.** A
`CiliumClusterwideNetworkPolicy` carrying explicit `ingressDeny`/`egressDeny` between
namespaces labelled `mcp.gateway/plane: tenant`. It is cluster-scoped, so no namespace-local
credential can touch it, and Cilium's deny rules take precedence over allows — which is
exactly the revocation semantic vanilla NetworkPolicy lacks. The primary lab cluster runs
Cilium v1.19.5 with the `ciliumclusterwidenetworkpolicies` CRD present, so this is testable
today rather than theoretical.

Cilium is **not** made a hard requirement: the shipped manifests are deliberately CNI-neutral
and must keep applying to a stock cluster. Tier 2 ships as an optional overlay, with the
difference in guarantee documented rather than blurred.

### 6. There is no inter-tenant exception mechanism

The deny is absolute. No supported configuration opens a network path from one tenant
namespace to another, and none is built pending a use case.

An earlier draft designed a provider-operated override — a labelled, narrow, time-boxed,
bilaterally-disclosed grant object. It was dropped because **no concrete circumstance
requiring one could be named.** Building it anyway would have added a security-relevant
subsystem on speculation: an object type that opens the boundary this ADR exists to close, an
audit and disclosure surface, and a reconciler to enforce expiry — because ⚠️ **Kubernetes
will not expire a NetworkPolicy.** There is no TTL on the object, so a "time-boxed" grant
with nothing actively reaping it is a permanent cross-tenant path that every compliance
dashboard reports as green. An escape hatch nobody uses is not free; it is attack surface
plus a maintenance obligation, guarding against a scenario that may not exist.

**If a real case appears, it gets its own ADR** — with the circumstance named, so the design
answers something concrete rather than anticipating everything. The reasoning above is
recorded so that a future reader finding no override does not assume it was an oversight and
add one back reflexively.

This also keeps the property in §3 clean: cross-tenant denial is a *consequence* of the
default, with no second mechanism that can partially undo it and nothing to enumerate,
review or expire.

### 7. Non-Kubernetes deployments

This ADR is Kubernetes-scoped. The Compose/Lite analogue of the same boundary is a
per-tenant Docker network plus a per-tenant project name; Lite is a single-tenant home
profile and is not a multi-tenant target, so it inherits the naming convention only if it is
ever operated as one of N. Embedded mode has no network boundary to configure and relies on
process and host separation, unchanged.

## Consequences

- **Positive:** the boundary ADR-0004 and ADR-0013 assume actually exists, and is measured
  rather than asserted; cross-tenant denial is the default rather than a maintained list;
  tenant identity stops leaking into cluster metadata, closing a hole straight through
  ADR-0013 §10's crypto-shred; the unpoliced-pod gap closes, so a foothold in a tenant
  namespace no longer has free rein in both directions; the provider plane's monitoring path
  becomes an explicit, reviewable exception instead of an accident of an open policy; and
  with no override mechanism (§6), the estate has exactly one standing cross-namespace path
  to reason about — the scrape — rather than that plus a population of grant objects whose
  expiry has to be trusted.
- **Negative / cost:**
  - **Pseudonymous namespaces are unreadable to operators by design.** Nobody can tell which
    namespace is which customer from `kubectl get ns`, and every incident begins with a
    lookup. This makes the provider plane's tenant map operationally load-bearing — losing it
    leaves N anonymous namespaces — which raises the priority of the BFF backup story that
    ADR-0011 deferred and ADR-0013 already flagged.
  - **Default-deny egress is the classic source of mystifying breakage.** DNS is the first
    casualty and it does not present as a network problem; it presents as an application that
    cannot resolve anything. The device-port allowlist problem the current file warns about
    gets sharper, not milder.
  - Tier 1's guarantee is RBAC-shaped. Stating that plainly is part of the decision; a reader
    who believes the network enforces it will make a wrong risk assessment.
  - **NetworkPolicy is namespaced**, so the default-deny must be applied into *every* tenant
    namespace at provision time. A namespace created outside the provisioning path is open
    until something notices — an argument for Tier 2, where the deny is cluster-scoped and
    covers namespaces nobody remembered to configure.
  - `deploy/kubernetes/` must be parameterized for the namespace, which touches every
    manifest and the kustomization.
  - **A legitimate inter-tenant need, if one ever arises, is blocked rather than
    inconvenient.** That is the accepted cost of §6: the answer is a new ADR and a code
    change, not a runbook step. Accepted deliberately, on the grounds that no such need is
    currently known and the boundary is worth more than the flexibility.
- **Follow-ups:**
  - File **F-68** in the findings register and **TG-10** in `testing-gaps.md`. TG-10's
    closing evidence is the inverse of the probe in §Context: the same cross-namespace curl
    must **fail**, from a tenant namespace, in both directions, and the Prometheus scrape
    must still succeed — verified on a live cluster, since nothing below that tier can see it.
  - Wire the environment variables `deploy/kubernetes/` still omits (`MCP_ALLOW_PRIVATE_TARGETS`,
    `MCP_ADMIN_KEY`, `MCP_VIEWER_KEY` — currently hand-applied on `mcp-gw` only, per the TG-7
    walk). Same file set, same change, and a fresh stack cannot be provisioned correctly
    without both.
  - Revise `multitenancy.md` and `kubernetes-architecture.md` on acceptance. The latter's
    *"Restricts ingress to port 8000"* row is the sentence that made this gap invisible.
  - This lands ahead of, or alongside, the providers UI (task #4). The provider plane
    delivers tenancy at the identity layer; this is the same boundary at the network layer,
    and the federation work wants a real boundary to test isolation against.

## Alternatives considered

- **Namespace named for the tenant** (`mcp-acme-corp`): rejected — §1. Readable, and it
  survives the crypto-shred that ADR-0013 §10 exists to provide, while leaking customer
  identity into every metric label, alert and dashboard in the estate.
- **Random UUID per namespace, recorded at allocation:** rejected. Opaque like the HMAC but
  not recomputable, so GitOps, a rebuild and an ADR-0011 restore all depend on a stateful
  allocation record whose loss is unrecoverable. The keyed HMAC recomputes from the tenant
  identifier and the key.
- **Keep the existing port-scoped policies:** rejected — that is the measured status quo, and
  it is open across namespaces on every listed port.
- **One namespace with per-tenant labels and policies:** rejected. It contradicts ADR-0004's
  load-bearing rule directly, and makes isolation depend on every future manifest remembering
  a label, which is the silent-failure shape ADR-0013 already identifies as most likely.
- **Require Cilium and ship only the clusterwide deny:** rejected as a hard requirement — the
  manifests must apply to a stock cluster — but adopted as the Tier 2 overlay, because it is
  the only option that gives the requested property against a tenant with namespace-write.
- **A service mesh with mTLS-based authorization instead of NetworkPolicy:** rejected as the
  primary mechanism. It is a much heavier operational dependency for a boundary that is
  already a hard namespace split, and it authorizes at L7 without removing L3 reachability.
  Complementary if a mesh is present for other reasons; not a substitute.
- **A provider-operated inter-tenant override:** rejected — §6. Designed in full in an
  earlier draft (labelled grant objects, narrow by construction, bilateral disclosure per
  ADR-0013 §9, a reaper for expiry) and dropped once it became clear no concrete use case
  existed to justify it. Reconsidering it requires a named circumstance and its own ADR.

## Implementation notes

Landed with the ADR, 2026-08-12. Recorded here because two of them changed the decision's
detail rather than merely realising it.

- **`tools/tenant_namespace.py`** computes the pseudonym. It **fails closed with no key**
  rather than falling back to an unkeyed hash: an unkeyed pseudonym is reversible by
  dictionary attack and is indistinguishable from a keyed one by inspection, so the
  insecure result must not be reachable by omission.
- **`deploy/kubernetes/`** is the base, with the namespace parameterized from
  `kustomization.yaml` alone — kustomize renames the `Namespace` object *and* retargets
  every resource, verified. No resource file hardcodes a namespace any more.
  `deploy/overlays/tenant-example/` is the per-tenant overlay; it must live outside the
  base directory, because kustomize rejects an overlay nested inside its own root as a cycle.
- **`servicemonitor.yaml` was a latent trap.** `namespaceSelector.matchNames` is a CRD
  field, which the namespace transformer does **not** rewrite, so every tenant would have
  scraped whichever namespace the file was written against. Omitting the selector — which
  means "my own namespace" — is the only form that survives a rename.
- **§3's device-egress rule changed shape during verification.** The first draft excluded
  all RFC-1918 space from the egress `ipBlock`. Measurement showed that breaks the product's
  normal case: devices legitimately live on the private LAN. The exclusion is now the
  **cluster's own pod and service CIDRs** — where other tenants are — plus link-local and
  loopback. This is the weakest part of Tier 1: `ipBlock` matches addresses, so it depends
  on those CIDRs being correct, and cannot separate tenants at all where the pod CIDR
  overlaps the device range. Tier 2 matches on identity and has neither problem.
- **The Tier-2 Cilium policy ships with an unresolved selector, deliberately visible.** A
  `CiliumClusterwideNetworkPolicy` is one cluster-scoped object and the selector language
  has no self-reference, so it cannot express "any tenant namespace other than the pod's
  own". The file documents both resolutions and recommends regenerating the namespace list
  from the provisioning path — a tenant missing from that list fails *closed*, which is the
  safe direction to get it wrong.
- **Verified on `mcp-gw`** (kind + Cilium v1.19.5): cross-namespace access to `:8000`,
  `:9100` and `:6379` all blocked where `:8000` previously returned `HTTP 200`; egress to a
  neighbouring namespace's pod IP blocked while the LAN device on `:9440` and the public
  internet stayed reachable; the monitoring namespace allowed on `:9100` and denied on
  `:8000`; the stack healthy with health checks still live. Full probe table in
  [testing-gaps.md TG-10](../testing-gaps.md), which also records what this does *not* prove.

## Open questions

One remains, and it blocks **Accepted**, in the shape ADR-0013 used.

### A. Is Tier 1 sufficient for GA, or is Tier 2 required for provider-operated estates?

Tier 1 is portable and honest but RBAC-shaped. Tier 2 is a real network guarantee and
narrows supported CNIs. The question is whether a provider-operated multi-tenant estate may
ship on Tier 1 alone, or whether Tier 2 becomes a documented precondition for operating one —
distinct from the single-tenant product, which needs neither.
