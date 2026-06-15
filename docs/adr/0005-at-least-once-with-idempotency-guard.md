# ADR-0005: At-least-once delivery + an at-most-once idempotency guard

- **Status:** Accepted
- **Date:** 2026-06-13 (reconstructed; guard shipped in F-08)
- **Related findings:** F-08, F-06, F-62

## Context

Tool calls flow over Redis Streams with a per-device consumer group. When a worker dies or
sheds a device, its pending entries are reclaimed (`XAUTOCLAIM`) by the new owner — this is
what makes delivery reliable. But reclaim means a call can be **delivered more than once**,
and a non-idempotent upstream operation (POST/PATCH) could then **double-execute** (e.g.
charge twice, create two records).

## Decision

We keep Redis Streams' **at-least-once** delivery (it is what gives us failover) and add an
**at-most-once guard for non-idempotent calls**, keyed on `request_id`, evaluated before
the upstream call:

- **Completion dedup (all methods):** if `result:{request_id}` exists, the call already
  finished — drop the reclaimed copy without re-running.
- **At-most-once for writes:** idempotency follows the HTTP method. The first executor of a
  non-idempotent call claims `exec:{request_id}` via `SET NX`; a later reclaim finds it set
  and **refuses**, publishing a `duplicate_suppressed` error so the client is told rather
  than left to time out. Idempotent methods (GET/HEAD/OPTIONS/TRACE/PUT/DELETE) re-run
  freely.

## Consequences

- **Positive:** reliable delivery *and* no gateway-introduced double side effects. The
  client always gets a definitive answer (result, or explicit duplicate-suppressed).
- **Negative / cost:** not end-to-end exactly-once against the *upstream* — that would need
  the device to honor an idempotency key (documented). The guard adds a Redis `SET NX` per
  non-idempotent call and TTL'd markers (`max(reclaim_min_idle*3, 120)s`).
- **Follow-ups:** pairs with lease-flap hysteresis (F-62) to reduce needless reclaims, and
  with admission control (F-06) to avoid backlog-driven trimming. Toggle via
  `registry.idempotency_guard`.

## Alternatives considered

- **Exactly-once delivery:** rejected — not achievable over Redis Streams without a
  distributed transaction; the guard gets the practical guarantee more cheaply.
- **Make every call idempotent by convention:** rejected — we don't control upstream
  semantics; method is the only signal we can trust generically.
