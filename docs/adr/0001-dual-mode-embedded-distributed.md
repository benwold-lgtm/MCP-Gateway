# ADR-0001: Dual-mode — embedded and distributed

- **Status:** Accepted
- **Date:** 2026-06-15 (reconstructed; decision predates the ADR register)
- **Related findings:** F-12, F-15, F-19

## Context

The gateway has two very different audiences: a developer evaluating it on a laptop, and a
production operator running it for a fleet. A laptop user wants zero infrastructure (no
Redis, one process, instant start). A production operator wants horizontal scale,
stateless ingress, and independent worker scaling. Serving both from one runtime risks a
god-object that branches on mode everywhere.

## Decision

We ship **one codebase with two modes**, selected by `registry.mode`:

- **embedded** (default): a single process. The `Registry` owns DevicePods in-process,
  persists registrations to SQLite, and routes tool calls directly — no Redis.
- **distributed**: a stateless gateway tier + a Redis control plane + a stateful worker
  tier (see [ADR-0002](0002-redis-control-plane.md)). Each scales independently.

The seam is an abstract registry backend (`MemoryRegistryBackend` vs
`RedisRegistryBackend`) and the `Registry`/`SpecService`/`PodSupervisor` collaborators, so
business logic is mode-agnostic where possible.

## Consequences

- **Positive:** trivial local onboarding; production gets true horizontal scale with a
  stateless ingress tier. The same translation/adapter/auth code runs in both.
- **Negative / cost:** some `if mode` branching remains (e.g. in-process dispatch vs
  stream publish; breaker readable only in embedded). Two code paths to test — the suite
  exercises both, integration tests gate distributed on real Redis.
- **Follow-ups:** the full embedded/distributed extraction (HealthMonitor/Provisioner
  split) is deferred (F-15/F-19); F-12 already split the `Registry` god-object into
  collaborators.

## Alternatives considered

- **Distributed-only** (always require Redis): rejected — kills the laptop/eval story.
- **Two separate products:** rejected — duplicates the translation/adapter/security core,
  which is the hard part and must stay identical.
