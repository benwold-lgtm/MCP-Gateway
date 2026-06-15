# ADR-0006: Fail-closed security gates in distributed mode

- **Status:** Accepted
- **Date:** 2026-06-11 (shipped in Tier-0 security)
- **Related findings:** F-23, F-24, F-53

## Context

The original defaults favored convenience: with no API keys configured, every request was
treated as an authenticated principal with all scopes (fail-**open**); and the gateway
would happily connect to an unauthenticated Redis. In a shared/production deployment both
are immediate takeover paths — an attacker who reaches the port or the Redis instance owns
the fleet and its stored credentials.

## Decision

In **distributed mode**, the gateway and workers **refuse to start** when a security
precondition is unmet, rather than running in an insecure posture:

- **No API keys configured ⇒ refuse to boot**, unless `gateway.allow_anonymous: true` is
  set explicitly (F-23). Anonymous access becomes a deliberate, visible opt-in.
- **Unauthenticated Redis (no password) ⇒ refuse to boot**, unless
  `redis.allow_insecure: true` (F-24). Production uses a password + `rediss://` TLS.

Embedded mode keeps the convenient single-operator default (fail-open is the documented
local posture) but now **warns loudly** at startup about permissive settings (F-53).

## Consequences

- **Positive:** the dangerous postures can't happen silently in production — the process
  won't start, which is the loudest possible signal. Security is the default, not an
  opt-in checklist item.
- **Negative / cost:** an operator who genuinely wants anonymous/insecure (closed test net)
  must set an explicit flag — intended friction. Misconfiguration surfaces as a failed boot
  (clear) rather than a running-but-open service (dangerous).
- **Important:** these gates are **independent of tenancy** — they hold even for a
  single-tenant stack (see [ADR-0004](0004-single-tenant-per-stack.md)).

## Alternatives considered

- **Warn but start:** rejected for distributed mode — a warning in logs is routinely missed;
  an open production gateway is unacceptable. (Embedded mode does warn-and-start, by design,
  for local dev.)
- **Always require auth, no override:** rejected — closed test nets and CI need an escape
  hatch; an explicit flag keeps it deliberate and auditable.
