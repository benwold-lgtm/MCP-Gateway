# ADR-0021: The provider console and the tenant console are separate applications

- **Status:** Proposed
- **Date:** 2026-08-17
- **Supersedes:** [ADR-0013](0013-two-plane-tenancy-and-the-provider-plane.md) §3 (plane
  immutability) as an enforced runtime property — see §3.

## Context

One BFF process can be a tenant's console or the provider's, decided by environment. Because
it can be either, it has accumulated three startup refusals to stop it being both:

- both identity providers configured in one process (ADR-0013 §2/§5);
- a session cookie widened beyond its host, which would collapse per-tenant subdomain
  isolation;
- (proposed, in the rejected ADR-0016) a tenant id alongside a routing registry.

Each is correct, each was written after noticing the crossing it prevents, and each guards the
same ambiguity. A fourth crossing being found later is the expected case, not the surprising
one — that is what a list of refusals against one ambiguity means.

The runtime carries the same shape. `session_plane()` reads a plane off every session and
defaults absent to tenant; `require_provider_scope` and `require_role` check the wall from
both directions; sessions are keyed under plane-scoped prefixes so one cannot be read as the
other. All of it is careful, and all of it exists because both kinds of session can exist in
one process.

## Decision

### 1. Two applications, two deployments, no shared request path

The provider console and the tenant console are separate services. Each has its own
identity provider configuration, its own session store, its own routes and its own hostname.
Neither contains code for the other's plane.

The ambiguity does not become better-guarded; it becomes **unrepresentable.** A tenant session
cannot appear in the provider application because the provider application has no tenant login,
no tenant routes and no tenant IdP configuration to authenticate one against.

### 2. Share the component library, not the process

The two consoles show many of the same things — a device list, a fleet view, diagnostics, tool
invocation. Duplicating those would produce two implementations that drift, which is the
standing bug ADR-0013 §5's shared-view reasoning was right to avoid.

So the **React component library and the generated API types are shared as a package**. What is
not shared is the running process, the session, the credential, or the route table. Sharing a
component is not a security boundary crossing; sharing a process is.

### 3. Plane immutability stops being a runtime property

ADR-0013 §3 fixes a session's plane at creation and never lets it change. Under §1 there is
nothing to fix: a session created by the provider application is a provider session because
that is the only kind that application makes.

The **defensive default is kept in the shared session code** — an absent plane still reads as
tenant, the plane with no cross-tenant authority — because it costs nothing and because a
shared library should fail in the safe direction wherever it is used. What goes is the
enforcement machinery: the two-directional wall checks, the plane-scoped store prefixes, and
the refusals that exist because both could be present.

### 4. Consequences for ADR-0017's model

Under [ADR-0017](0017-provider-authority-is-delegated.md), a provider operator with a
delegated support grant enters the **tenant's** console — the same application that tenant's
own staff use, at the tenant's hostname, writing to the tenant's audit.

That is a natural fit for this split rather than a complication of it. The tenant console
authenticates against the tenant's IdP; a delegated provider operator is a principal that IdP
now recognises for a bounded period. The provider console never needs a tenant session,
because a provider operator doing tenant work is not using the provider console.

## Consequences

- **Positive: three startup refusals and the plane wall stop being necessary.** They were
  compensating for a shape, and the shape is gone.
- **Positive: the two applications can have different security postures** — shorter sessions,
  mandatory MFA and tighter concurrency limits on the provider console, which ADR-0013 §14
  flagged as wanted and which is awkward to apply selectively inside one process.
- **Positive: a vulnerability in one console is not automatically a vulnerability in the
  other**, which was never true of one process serving both.
- **Negative: two deployments to build, ship, version and upgrade**, including two container
  images and two sets of manifests. The shared package must be versioned properly, which is
  more discipline than an internal import.
- **Negative: a shared component package is a new coupling with its own failure mode** — a
  breaking change lands in two applications at once. Mitigated by the package being *views*,
  with no session, credential or route knowledge in it.
- **Negative: the lab and CI setups need rework**, since a single BFF currently serves both
  consoles depending on environment.

## Alternatives considered

**Keep one process and add the fourth refusal when the fourth crossing is found.** The status
quo, and it has worked. Rejected because "add a guard each time we notice a crossing" has no
end condition, and because the guards are individually cheap while the reasoning they require
of every future contributor is not.

**One process, but plane decided per request from the hostname** rather than from
configuration. Removes the deployment duplication and keeps one image. Rejected: it makes the
plane a property of a request rather than of a process, so every piece of shared state —
session store, caches, connection pools, rate limiters — becomes a place two planes meet. That
is more surface than the split it avoids.

**Separate processes but a shared session store.** Convenient for an operator who is both a
provider engineer and a tenant admin. Rejected: a shared session store is the crossing, wearing
a different hat.

## Open questions

- **Whether the shared package is published or vendored.** Publishing is cleaner and slower;
  vendoring is faster and rots. Probably a workspace package while both live in one
  repository, revisited if they separate.
- **Whether break-glass (ADR-0017 §4) lives in the tenant console or a third, minimal
  application.** A third application is more defensible — it can be offline by default and
  reachable only from a management network — but three deployments to serve a rare path is a
  real cost. Not decided here.
