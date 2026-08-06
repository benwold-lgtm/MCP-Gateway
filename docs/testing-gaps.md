# Testing gaps — what we have not empirically validated

This document exists to stop **"designed and reasoned about"** from being quietly read as
**"verified."** Everything listed here is implemented and unit-tested, but has never been
exercised against the conditions it was built for, because doing so needs infrastructure
this project does not have.

That distinction matters most exactly where it is easiest to lose: a resilience feature
that has never seen a real fault is a hypothesis. Recording the gap is cheap; discovering
it during an incident is not.

**This is a living document.** When you find something you cannot properly test, add a row
— see [Adding an entry](#adding-an-entry). Removing a row requires evidence, not
confidence: link the run, the baseline, or the recording that closed it.

## Status at a glance

| ID | Gap | Blocked on | Risk if the design is wrong |
|----|-----|-----------|------------------------------|
| [TG-1](#tg-1--chaos--fault-injection-f-63) | Chaos / fault injection (E1–E10) | A live multi-node platform + fault injector | Documented failure-mode mitigations may not behave as written under real faults |
| [TG-2](#tg-2--scale-and-performance-baseline) | Scale + performance baseline | Multi-node cluster, a realistic upstream, sustained load capacity | No capacity model; HPA thresholds and pool sizes are educated guesses |
| [TG-3](#tg-3--ha-redis-failover) | HA Redis failover behaviour | A real Sentinel/Cluster deployment able to promote a replica | The retry/health-check settings may not cover a real election window |
| [TG-4](#tg-4--the-kubernetes-manifests-on-a-real-cluster) | The k8s manifests on a real cluster | Any conformant cluster with an ingress controller | Manifests that build may still not *run*; ordering/permission faults are invisible |
| [TG-5](#tg-5--the-arm64-image-on-real-arm64-hardware) | arm64 image on real arm64 hardware | A Pi / arm64 host | QEMU-built arm64 layers can pass build and still fail at runtime |
| [TG-6](#tg-6--hash-reading-redis-paths-in-the-unit-tier) | Hash-reading Redis paths in the unit tier | A fakeredis fix, or moving the test to the real-Redis tier | Unit tests cannot exercise any `hgetall` consumer; a regression there surfaces only in the integration tier |

---

## TG-1 — Chaos / fault injection (F-63)

**What is unvalidated.** Every resilience claim in
[failure-modes.md](failure-modes.md): worker-kill reassignment, Redis flap recovery,
blast-radius containment on a slow upstream, breaker open/half-open transitions, lease-flap
convergence, SSE resume after a gateway kill, and degraded-mode behaviour at zero workers.

**Why we cannot test it here.** The experiments need a live multi-node platform plus a fault
injector (Toxiproxy or equivalent) sitting between the gateway, Redis and the upstreams.
Killing pods and partitioning a network are not things a single-box test suite can do
honestly — a mocked partition proves the mock, not the system.

**What exists instead.** A written experiment plan, **E1–E10**, with a predicted-behaviour
table and the specific metric each experiment should move. It is analysis, not evidence, and
the [CHANGELOG](../CHANGELOG.md) known-limitations section says so.

**What would close it.** Run E1–E10 against a real deployment and record the observed
behaviour beside the predicted one. Disagreements are the valuable output — a prediction
that holds teaches less than one that does not.

**Prerequisite.** [TG-2](#tg-2--scale-and-performance-baseline) first: chaos results are
uninterpretable without a healthy baseline to compare against.

## TG-2 — Scale and performance baseline

**What is unvalidated.** Throughput and latency under load, and therefore every number
derived from them: connection-pool sizes, the HPA thresholds, the admission-control
watermark, `max_concurrent_calls_per_device` / `_per_worker`, and the SSE pub/sub pool
sizing. These are reasoned defaults, not measured ones.

**Why we cannot test it here.** A meaningful baseline needs a multi-node cluster, an upstream
that behaves like a real API (latency distribution, rate limiting, connection limits), and
enough sustained load to reach saturation. Single-box numbers mostly measure the box.

**What exists instead.** A runnable load harness ([tools/loadtest/](../tools/loadtest/)) and
a methodology with a results template in [load-testing.md](load-testing.md). The template
has **no rows filled in** — that emptiness is the gap.

**What would close it.** Fill in the baseline table for at least one realistic environment,
recorded *with* its environment — a number without its context cannot be compared against a
later one. Then revisit the tuning defaults above against the measurements.

## TG-3 — HA Redis failover

**What is unvalidated.** Whether the client's failover handling actually covers a real
primary election. Redis is the entire distributed control plane, so this is the single
highest-consequence gap on the list.

**Why we cannot test it here.** It needs a genuine Sentinel or Cluster deployment that can
promote a replica. **A `docker restart` of a single Redis is not a substitute, and it is
worth being precise about why:** a clean container restart closes sockets cleanly, so
redis-py's pool simply discards dead connections and reconnects on next use. Both the old
unconfigured client *and* the current one recover from it identically — the scenario cannot
distinguish them, so passing it proves nothing about failover. The conditions that actually
exercise the new settings are a half-open connection left by an abrupt primary loss, and a
command issued *during* the election window.

**What exists instead.** Unit tests asserting the retry *policy semantics* — that transient
connection errors and timeouts recover, that a permanent outage still surfaces, that the
budget is finite — plus health-check and connect-timeout settings. The policy is tested; the
event is not.

**Specifically unverified:**

- Whether the default retry budget (~2.5s, jittered) covers a real election. It is
  deliberately sized *not* to block through a long Sentinel promotion, so some hard errors
  during a slow failover are expected behaviour — but nobody has watched where that line
  actually falls.
- Whether jitter meaningfully prevents a reconnect thundering herd across many replicas and
  workers reconnecting at once. This is the reason jitter is there.
- Whether `health_check_interval` catches half-open pooled connections before real traffic
  does.

**What would close it.** Stand up Sentinel or a managed HA Redis, force a promotion under
load, and record: error count and duration during the window, reconnect latency distribution
across replicas, and whether a retried command ever double-executed (the idempotency guard
should absorb it — confirm that it does).

## TG-4 — The Kubernetes manifests on a real cluster

**What is unvalidated.** That `deploy/kubernetes/` actually *runs*. `kubectl kustomize`
builds it and the manifest invariants are unit-tested, but building is not deploying:
ordering, RBAC/permissions, PVC binding, probe timing, ingress admission and the
NetworkPolicy rules are all invisible to a local build.

**Why we cannot test it here.** No cluster available.

**What exists instead.** `kubectl kustomize` build verification, and
`tests/test_deploy_manifests.py` asserting image-pinning invariants. Both are static.

**Note.** This gap has already produced a real defect: the docs instructed users to pin an
image tag that returns 404, which a single `kubectl apply` would have caught immediately.
Static checks did not, because the tag was syntactically fine.

**What would close it.** `kubectl apply -k deploy/kubernetes` on any conformant cluster,
through to healthy pods, a passing `/readyz`, and one successful tool call via the ingress.

## TG-5 — The arm64 image on real arm64 hardware

**What is unvalidated.** That the published `linux/arm64` image runs on an actual arm64 host
— which is the whole point of the lite/home profile.

**Why we cannot test it here.** No arm64 hardware; the image is cross-built on an amd64
runner under QEMU emulation.

**What exists instead.** A successful multi-arch build and push. A QEMU-built layer can
build cleanly and still fault at runtime on real silicon, typically in a native dependency.

**What would close it.** `docker compose -f docker-compose.lite.yml up` on a Pi or other
arm64 box, through to a registered device and a successful tool call.

## TG-6 — Hash-reading Redis paths in the unit tier

**What is unvalidated.** Nothing, in the end — but not where you would expect, and the
detail matters to anyone adding a test.

**The trap.** `fakeredis` 2.36 does **not** honour `decode_responses=True` for `hgetall`,
while honouring it for `get`, `smembers` and the rest. Hash reads come back with `bytes`
keys and values:

```
get        -> 'v'
smembers   -> {'m'}
hgetall    -> {b'a': b'1'}
```

Every `DeviceConfig.from_redis_hash` consumer therefore raises `KeyError: 'hostname'` under
fakeredis, so `RedisRegistryBackend.get_device` — and anything downstream of it, including
the worker's `_spawn_pod` config read — **cannot be unit-tested against the fake.** This is
easy to mistake for a bug in the code under test; it is not.

**What exists instead.** CI runs a real `redis:7-alpine` service and the integration tier
(`tests/test_integration_redis.py`) exercises these paths for real, so they are covered —
just not by the unit tier. A test needing a device config from a backend should either use
`MemoryRegistryBackend` (when the point is the logic, not the serialisation) or the
`real_redis` fixture (when the point *is* the serialisation).

**What would close it.** A fakeredis release that decodes hash replies, or a small decoding
wrapper in `conftest.py`. Neither is urgent while CI has a real Redis; the cost of the gap
is confusion, not missing coverage.

**Risk if the design is wrong.** Low for correctness, real for velocity: the failure mode
looks like a product bug, and the natural "fix" is to weaken the test.

---

## Adding an entry

Add a row to the table and a section, keeping the same five headings:

- **What is unvalidated** — the specific claim, not the feature name. "Worker reassignment
  completes within ~90s under load" is useful; "resilience" is not.
- **Why we cannot test it here** — the concrete missing resource. If it turns out something
  *could* be tested with what we have, that is a bug in this document; test it instead.
- **What exists instead** — the analysis, unit tests, or static checks standing in, and
  plainly what they do *not* cover.
- **What would close it** — the specific run and the evidence it should produce.
- **Risk if the design is wrong** — what breaks in production, so the row can be prioritised
  against everything else rather than sitting here indefinitely.

Two rules worth keeping:

1. **Be precise about what a partial test does and does not prove.** TG-3 is the model: a
   `docker restart` looks like a failover test and is not one. A gap recorded as "partly
   tested" without saying which part is worse than no row at all, because it reads as
   reassurance.
2. **Closing a row needs evidence, not confidence.** Link the run, the recorded baseline, or
   the incident. If the result contradicted the prediction, say so and keep the row until
   the design is fixed.
