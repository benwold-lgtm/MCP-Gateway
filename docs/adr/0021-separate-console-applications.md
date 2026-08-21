# ADR-0021: The provider console and the tenant console are separate applications

- **Status:** Accepted
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

### 5. Addressing is by hostname, never by port

Each console is reached at its own **hostname**, on 443, behind the same ingress. Ports are an
implementation detail inside the cluster and are never the thing that separates the two
applications.

This is not a preference, and it is the one place where getting it wrong would quietly undo
the split. **Cookies do not isolate by port.** RFC 6265 §8.5 is explicit:

> cookies do not provide isolation by port. If a cookie is readable by a service running on
> one port, the cookie is also readable by a service running on another port of the same
> server.

So `console.example.com:8443` and `console.example.com:9443` are one cookie jar. Splitting the
consoles across ports would give two applications, two processes, two IdPs — and a single
shared session cookie between them, which is precisely the crossing this ADR exists to make
unrepresentable. It would also silently undo the host-scoping the BFF now refuses to start
without.

The scheme is therefore:

| | Host | Notes |
|---|---|---|
| Tenant console | `t-7f3a91c4.console.example.com` | Per-tenant, which ADR-0013 §2 already relies on to select the tenant's IdP without asking the user to name themselves. Opaque per [ADR-0019](0019-opaque-tenant-identity.md) |
| Provider console | `provider.example.com` | One host for the estate |

Each console stays **same-origin with its own BFF** — its nginx proxies `/api` and `/auth`
under its own hostname — so neither needs CORS, and the cross-origin machinery that would
otherwise appear never does.

### 6. The browser enforces host scoping, not just our startup check

The session cookie takes the **`__Host-` prefix**. A cookie so named is rejected by the
browser unless it is `Secure`, has `Path=/`, and carries **no `Domain` attribute** — which is
exactly the property the BFF currently protects with a startup refusal on `COOKIE_DOMAIN`.

Both are kept, and they are not redundant. The startup refusal catches a *deployment* trying
to widen the cookie and explains why. The prefix means that even if something else on the
parent domain sets a cookie of the same name, it cannot be a `__Host-` one, so it cannot
shadow the real session.

That second case is the reason this matters when the two consoles are siblings under one
parent. A compromised or taken-over sibling — `status.example.com`, say — cannot *read* a
host-scoped cookie, but it can **set** one scoped to `.example.com` and have the provider
console receive it. Cookie forcing of that kind is a real attack on a shared parent domain,
and the prefix is what closes it.

**Separate registrable domains are stronger still** and are the recommendation for a
provider-operated estate: putting the consoles on different sites removes the shared parent
entirely, and makes the browser treat any interaction between them as cross-site for
`SameSite` purposes. Siblings under one parent are acceptable *with* the prefix; they are not
acceptable without it.

### 7. Development uses hostnames too

The tempting shortcut — `localhost:5173` for one console and `localhost:5174` for the other —
reproduces the port mistake from §5 in the environment where the code is actually written. Two
dev servers on one host share a cookie jar, so a developer would see two consoles that appear
isolated while sharing a session, and the first environment capable of revealing the defect
would be production.

Development and CI therefore use hostnames, resolved however is convenient — the lab already
does this for its identity providers via `nip.io`, and the same mechanism serves here. This
costs a few lines of setup and buys an environment whose isolation properties are the same
shape as the real one.

### 8. Break-glass is the third application

[ADR-0017](0017-provider-authority-is-delegated.md) §4 keeps break-glass as the one unilateral
path into a tenant's stack. It gets its **own minimal application**, not a route inside either
console.

The cost is real and recurring — a third deployment, image and manifest set to serve a path used
rarely — and it is accepted, because this ADR's own reasoning points directly at it. §1 splits
the consoles so that a crossing becomes *unrepresentable* rather than guarded. Folding the
highest-consequence path in the system into either console reintroduces exactly the ambiguity
that reasoning exists to remove, on the one path ADR-0017 §4 requires to be impossible to use
quietly. Three deployments is an operational cost; the alternative is an architectural
regression, and those are not the same kind of thing to trade.

A separate application also buys properties neither console can offer, because they exist to be
reachable and this exists not to be:

- **offline by default**, started deliberately rather than always listening;
- **reachable only from a management network**, which is a sentence that cannot be written about
  a tenant-facing console;
- its own authentication posture, without weighing it against everyday usability;
- an audit surface small enough to review in full.

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
  consoles depending on environment — and per §7 that rework is hostname-based, which is more
  than a port change.
- **Negative: per-tenant DNS and certificates become a hard dependency** rather than a
  consequence noted in ADR-0013. Wildcard certificates cover the tenant consoles; the provider
  console needs its own.

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
- **Whether the two consoles should share a registrable domain at all.** §6 says separate is
  stronger and siblings are acceptable with the `__Host-` prefix; which one an estate uses
  interacts with branding and certificate management more than with security.
- **How the break-glass application is started when it is off by default** (§8). An operator
  who must first deploy something in order to respond to an outage has a slower emergency stop
  than one who must only reach a restricted network. Where that line sits is undecided.
