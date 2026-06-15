# ADR-0002: Redis Streams + pub/sub as the distributed control plane

- **Status:** Accepted
- **Date:** 2026-06-15 (reconstructed)
- **Related findings:** F-06, F-07, F-08, F-10, F-24, F-31

## Context

Distributed mode needs a shared substrate for: the device registry, work assignment
(which worker owns which device), tool-call delivery from a stateless gateway to the
owning worker, and result delivery back to whichever gateway replica holds the client's
SSE stream. The gateway tier must stay stateless so it scales freely; workers must be able
to claim devices and survive each other's deaths.

## Decision

We use **Redis** as the single control plane:

- **Registry:** device configs in hashes (`device:{h}`), set membership in `devices:all`.
- **Assignments:** a shared consumer-group stream (`device:assignments`) — workers claim
  devices via leases (`claim:{h}`).
- **Tool calls:** a per-device stream `device:{h}:calls` (consumer group per device);
  results via pub/sub on `session:{sid}:results` so any replica can relay them.
- **Coordination:** leader election (reconciler, gauge refresh) via Redis locks.

## Consequences

- **Positive:** stateless gateway tier; workers scale and fail independently; streams give
  us at-least-once delivery, backlog visibility (consumer-group lag → admission control
  F-06), and a natural dead-letter target (F-10).
- **Negative / cost:** Redis is a hard dependency and the stack's primary SPOF — it must
  run authenticated + TLS (F-24/F-31) and ideally HA. At-least-once delivery forces an
  idempotency guard for writes ([ADR-0005](0005-at-least-once-with-idempotency-guard.md),
  F-08). Stream `MAXLEN` trimming is a silent-loss risk, mitigated by admission control.
- **Follow-ups:** sticky claims need rebalancing on scale-out (F-07); lease flap needs
  hysteresis (F-62).

## Alternatives considered

- **A real message broker (Kafka/RabbitMQ/NATS):** rejected for v1 — heavier operational
  surface; Redis already needed for shared state, and streams cover the delivery needs.
- **A database + polling:** rejected — higher latency, no native consumer groups/pub-sub.
- **Direct gateway→worker RPC:** rejected — re-introduces gateway statefulness (must track
  worker topology) and a discovery problem Redis already solves.
