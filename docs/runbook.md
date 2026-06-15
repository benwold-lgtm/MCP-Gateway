# Operations Runbook & Troubleshooting — Device MCP Gateway

The on-call companion to the [failure-mode matrix](failure-modes.md). That doc says
*what can break and how it's detected*; this one says *what to do when the pager goes
off* — triage steps and the exact commands to remediate. It is organized two ways:

1. **[Alert playbooks](#alert-playbooks)** — one entry per Prometheus alert in
   `deploy/kubernetes/prometheus-rules.yaml`.
2. **[Symptom troubleshooting](#symptom-troubleshooting)** — for reports that arrive
   without an alert ("a client says tool calls hang").

Plus the **[standard procedures](#standard-procedures)** the playbooks call into
(scale, rotate the secret key, work the DLQ, roll a restart).

Conventions used below:

```bash
KEY=...                       # a gateway API key with the needed scope
H=...                         # a device hostname
GW=https://gateway.internal   # gateway base URL
NS=mcp                        # Kubernetes namespace
```

Distributed mode is assumed (Redis + workers). Embedded mode is a single process —
most control-plane alerts don't apply; the troubleshooting section calls out which.

---

## Alert playbooks

Each alert below maps to a row in [failure-modes.md](failure-modes.md) (the `#` column).
Sev: 🔴 page · 🟠 ticket · 🟡 watch.

### `MCPNoLiveWorkers` 🔴 (W1)

No worker is scraping / all workers down → tool calls hang to timeout.

```bash
kubectl -n $NS get pods -l app=device-mcp-worker
kubectl -n $NS logs -l app=device-mcp-worker --tail=100 | grep -iE 'redis|assert_redis|refus'
```

- Workers crashlooping on the **F-24 Redis-auth gate** ("refusing to start … unauthenticated
  Redis") → the `redis-url`/`redis-password` secret is wrong or missing. Fix the secret,
  not the gate. See [Standard procedures → Fix the Redis secret](#fix-the-redis-secret).
- Workers up but `mcp_worker_pods` absent → they can't reach Redis or the metrics port
  isn't scraped. Check `kubectl -n $NS exec` → `redis-cli -a … ping` and the ServiceMonitor.
- Genuinely scaled to zero → [scale workers up](#scale-workers).

### `MCPToolCallErrorBudgetBurnFast` 🔴 / `…BurnSlow` 🟠

Tool-call success SLI (`ok/(ok+error)`) is burning the 99.5% budget. Fast = sharp
outage (page); slow = a leak (ticket).

```bash
# Which devices / error types dominate?
curl -s "$GW/metrics" | grep -E 'mcp_tool_calls_total|mcp_circuit_breaker_opens_total'
```

1. Is it one device or fleet-wide? One device + `MCPCircuitBreakersOpen` → upstream
   fault, work that device (below). Fleet-wide → look at Redis (`MCPNoLiveWorkers`,
   readiness) and a recent deploy.
2. Remember the **success-SLI caveat**: upstream client-fault **4xx counts as `error`**
   (documented in [observability.md](observability.md)), so a client sending bad args
   can burn budget without anything being "down". Check the access log for 4xx-heavy
   callers before declaring an incident.

### `MCPDispatchReliabilityLow` 🔴 (D4/D6)

`1 − (timeouts + dead_letters)/dispatched` < 99.9%. Calls are dispatched but not
completing — distinct from upstream errors.

```bash
curl -s "$GW/metrics" | grep -E 'mcp_tool_call_timeouts_total|mcp_dead_letter_total'
```

→ Usually pairs with `MCPDeadLetterGrowing` (pod-replace window) or a slow upstream
(`MCPCircuitBreakersOpen`). Work whichever co-fires.

### `MCPDeadLetterGrowing` 🟠 (D6)

Undeliverable calls are accumulating in `device:{H}:calls:dead` (typically "no active
pod" during a pod replace). Full procedure: [observability.md → Working a dead-letter
alert](observability.md#working-a-dead-letter-alert-f-10). Short form:

```bash
curl -H "Authorization: Bearer $KEY" "$GW/v1/devices/$H/deadletter"          # inspect
curl -X POST -H "Authorization: Bearer $KEY" "$GW/v1/devices/$H/deadletter/replay"  # replay once a pod is back
curl -X DELETE -H "Authorization: Bearer $KEY" "$GW/v1/devices/$H/deadletter"       # drain
```

Confirm a pod is actually serving the device (`GET /v1/devices/$H`) **before** replaying,
or the replay just dead-letters again.

### `MCPUndeliveredBacklogNearMaxlen` 🟠 (R3)

`mcp_worker_undelivered_calls` > 8000 — approaching the 10k stream MAXLEN where the
oldest undelivered calls are silently trimmed.

1. [Scale workers](#scale-workers) — the consumer group is behind.
2. Find the stuck consumer: `redis-cli -a … XINFO GROUPS device:$H:calls` (look for a
   consumer with a large `pending` / old `idle`).
3. Admission control (F-06) should already be shedding with 429s
   (`MCPAdmissionShedding`); if not, check `registry.call_backlog_limit` isn't `0`.

### `MCPAdmissionShedding` 🟡 (G3)

`mcp_calls_rejected_overload_total` rising — the gateway is fast-failing calls with
`429 + Retry-After` because a device's worker backlog passed the watermark. **This is
working-as-intended back-pressure, not an outage.** Scale workers / fix the slow upstream;
the shedding stops on its own once the backlog drains.

### `MCPCircuitBreakersOpen` 🟠 (D2)

`mcp_circuit_breaker_opens_total` rising — a device returned 5xx repeatedly and its
breaker opened (callers now get a fast 503 instead of a 15s hang).

```bash
curl -H "Authorization: Bearer $KEY" "$GW/v1/devices/$H/diagnostics"   # reachability, spawn_error
```

→ Fix the upstream. The breaker **auto-resets after 60s**; no operator action is needed
to close it. Repeated reopens = upstream still unhealthy.

### `MCPReconcilerLeaderAbsent` / `MCPGaugeLeaderAbsent` 🟠 (W4)

`sum(mcp_reconciler_leader) == 0` — no worker holds the reconciler/gauge lease, so
orphaned-device recovery (and gauge refresh) stalls.

→ Almost always a Redis-connectivity blip across all workers. Check worker→Redis
reachability; the lease re-elects with jitter (F-21/F-61) once any worker reconnects.
If it persists, restart one worker to force an election.

### `MCPReconcilerReassignmentChurn` 🟠 (W3)

`mcp_reconciler_reassignments_total` climbing — claim-leases are flapping (a GC pause or
Redis latency exceeding the claim TTL), causing device churn between workers.

→ Raise `registry.claim_ttl` and/or `registry.reconcile_orphan_grace_cycles` (hysteresis,
F-62), and investigate worker GC pauses / Redis latency. Churn is self-limiting but wastes
work and can briefly double-own a device.

### `MCPDeviceToolsBreakingChange` 🟠 (D7)

`mcp_device_tools_changed_total{breaking}` — a device's spec changed in a
backward-incompatible way; live clients pinned to the old tool surface will fail.

```bash
# What changed and who did it
curl -H "Authorization: Bearer $KEY" "$GW/v1/devices/$H" | jq '.tools_revision'
grep '"action":"device.tools_changed"' logs/audit.log | tail
```

→ Notify affected clients; clients re-poll `tools_revision` to pick up the new surface.
See [api-change-governance.md](api-change-governance.md).

---

## Symptom troubleshooting

Reports that arrive without a specific alert.

### "Tool calls hang, then time out (~30s)"

The call was accepted but never completed. In order of likelihood:

1. **No worker owns the device.** `curl .../v1/devices/$H` — is a pod assigned/reachable?
   If no live workers → `MCPNoLiveWorkers` path. If the device is unassigned, the
   reconciler should claim it; check `MCPReconcilerLeaderAbsent`.
2. **Backlog/shedding.** A 429 (not a hang) means admission control is shedding — scale
   workers. A true hang with backlog → `MCPUndeliveredBacklogNearMaxlen` path.
3. **Slow upstream.** `GET /v1/devices/$H/diagnostics` for reachability; a breaker that
   keeps reopening points at the device.
4. The client gets a structured timeout error carrying the **`rid`** — grep it in the
   access log (`rid=…`) to follow the exact call across gateway → worker.

### "A device shows `reachable: false` / its tools fail" (D1)

```bash
curl -H "Authorization: Bearer $KEY" "$GW/v1/devices/$H/diagnostics"
```

Check, in order: `base_url` reachable from a worker pod; the spec URL fetches and is
under `registry.spec_max_bytes` (F-09); credentials decrypt (no `MCP_SECRET_KEY`
mismatch — see [secret-rotation.md](secret-rotation.md)); `spawn_error` in the device
record names the failure.

### "Clients are getting 429s"

Two different 429s — distinguish by the `Retry-After` and the metric:

- **Admission shedding** (`mcp_calls_rejected_overload_total`) — the device's worker
  backlog is too deep. Scale workers / fix the upstream.
- **Per-IP / per-principal rate limit** (F-16) — that *caller* exceeded its limit. Raise
  the limit if it's a false positive, else it's working as intended.

### "The gateway or worker won't start" (R2)

Distributed mode **fails closed** by design. Read the first error line:

| Refusal | Cause | Fix |
|---------|-------|-----|
| "refusing to start … no API keys" (F-23) | distributed mode with no auth configured | set an API key, or `gateway.allow_anonymous: true` only if you truly mean open access |
| "refusing … unauthenticated Redis" (F-24) | Redis URL has no password | [fix the Redis secret](#fix-the-redis-secret), or `redis.allow_insecure: true` for a trusted-network lab |
| config-validation **warnings** (F-50) | unknown/misplaced config keys | warnings don't block startup; fix the dotted path the warning names |

Do **not** reach for the bypass flags (`allow_anonymous`, `allow_insecure`) to clear a
prod alert — they disable a release-blocking control. They exist for local/lab only.

### "Encrypted credentials suddenly unreadable"

A `MCP_SECRET_KEY` change without rotation. The codec accepts **multiple keys** — add the
old key back (`MCP_SECRET_KEY="<new>,<old>"`) and the gateway decrypts again immediately.
Then run the zero-downtime [rotate procedure](#rotate-the-secret-key). If the key is lost
entirely, the at-rest credentials are unrecoverable — re-register the devices' credentials.

---

## Standard procedures

### Scale workers

Each worker owns a disjoint set of devices (single-owner, D-2); scaling out triggers a
decentralized rebalance (F-07).

```bash
kubectl -n $NS scale deploy/device-mcp-worker --replicas=<n>
# or rely on the HPA; confirm the new pods pick up devices:
curl -s "$GW/metrics" | grep mcp_worker_pods
```

Scaling **in** is safe — a removed worker's devices are reclaimed by the reconciler
(F-07). Don't scale gateway via `--scale` in Compose (fixed host port); scale it via
Kubernetes/LB.

### Fix the Redis secret

```bash
kubectl -n $NS get secret mcp-redis -o jsonpath='{.data.redis-url}' | base64 -d; echo
# update redis-url (must include the password) and redis-password, then:
kubectl -n $NS rollout restart deploy/device-mcp-gateway deploy/device-mcp-worker
```

The F-24 gate (`assert_redis_secure`) refuses an unauthenticated URL — the fix is a correct
secret, not the `redis.allow_insecure` escape hatch.

### Rotate the secret key

Zero-downtime, multi-key flow — full detail in [secret-rotation.md](secret-rotation.md):

1. Deploy with **both** keys, new first (`MCP_SECRET_KEY="<new>,<old>"`).
2. `device-mcp-rotate-secrets --config config.yaml` (idempotent, loss-free; run once per stack).
3. When it reports `0 failed`, redeploy with the new key only.

### Work the dead-letter queue

See [`MCPDeadLetterGrowing`](#mcpdeadlettergrowing--d6) above and
[observability.md](observability.md#working-a-dead-letter-alert-f-10).

### Roll a restart

```bash
kubectl -n $NS rollout restart deploy/device-mcp-gateway   # gateway: stateless, safe anytime
kubectl -n $NS rollout restart deploy/device-mcp-worker    # workers: devices rebalance during the roll
```

A gateway replica that loses an in-flight SSE stream drops it; the client reconnects and
retries (F-20, accepted). For version upgrades follow [upgrade.md](upgrade.md), not a bare
restart.

### Verify the audit trail

```bash
python -m device_mcp_gateway.audit_verify logs/audit.log    # exit 0 = chain intact (F-57)
```

---

## Escalation & SPOFs

Before paging the next tier, capture the `rid` of a failing call, the firing alert, and
the output of `GET /v1/devices/$H/diagnostics` for the affected device. The single points
of failure to keep in mind during any incident (full list in
[failure-modes.md](failure-modes.md#6-single-points-of-failure)):

- **Redis** — the whole control plane. Run it HA/replicated.
- **`MCP_SECRET_KEY`** — losing it makes at-rest credentials unrecoverable. Back it up
  out-of-band.
