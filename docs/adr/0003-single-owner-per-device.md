# ADR-0003: Single-owner per device

- **Status:** Accepted
- **Date:** 2026-06-14 (Decision D-2 in the findings register)
- **Related findings:** F-03, F-08, F-07, F-18

## Context

A "hot" device with high tool-call QPS can saturate the single worker that owns it (one
consumer × the per-device concurrency cap). The obvious scaling answer is to **shard** a
device across multiple worker pods. But several correctness properties depend on a device
having exactly one owner at a time.

## Decision

A device is **owned by exactly one worker** at any moment. We do **not** shard a single
device across pods. A hot device scales **vertically** (`max_concurrent_calls_per_device`,
a bigger worker) or via **operator-level fan-out** (register the same upstream as two
logical devices). Per-principal rate-limiting/fairness is deferred to F-16.

## Consequences

- **Positive:** single-ownership is load-bearing for **at-most-once writes** (F-08),
  **per-device ordering**, **one circuit breaker per device** (F-18), and clean
  **lease failover / rebalancing** (F-07). Keeping it intact keeps all four simple.
- **Negative / cost:** a single device's throughput has a ceiling (F-03). Accepted: the
  upstream API is almost always the first bottleneck, and the vertical/fan-out escape
  hatches cover the rare case.
- **Follow-ups:** F-03 downgraded 🔴→accepted; F-18 (per-worker breaker) stays accepted
  precisely because we never shard. Documented in
  [kubernetes-architecture.md](../kubernetes-architecture.md).

## Alternatives considered

- **Shard a device across N pods:** rejected — fractures ordering, the per-device breaker,
  and at-most-once writes for a rarely-needed capability; the gain rarely justifies it.
- **Stateless workers with a shared per-call lock:** rejected — per-call coordination cost
  and still doesn't give clean ordering.
