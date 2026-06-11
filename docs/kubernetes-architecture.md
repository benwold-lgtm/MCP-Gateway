# MCP Gateway — Kubernetes Deployment Architecture

This document describes how the **Device MCP Gateway** is deployed on Kubernetes in **distributed mode** and traces the complete message path from an LLM client through the gateway to downstream device APIs.

Distributed mode is the production path: stateless gateway replicas read from Redis, while stateful workers own the DevicePods that make the actual HTTP calls to device APIs. All three tiers scale independently.

---

## Deployment Overview

```mermaid
flowchart TB
    LLM[/"LLM Client\nClaude Desktop · Cursor · API Application"/]

    subgraph CLUSTER["Kubernetes Cluster"]
        subgraph NS["Namespace: mcp-gateway"]

            ING["Ingress\nnginx.ingress.kubernetes.io\nHost: mcp-gateway.example.com\nTLS termination"]

            SVC["Service: device-mcp-gateway\ntype: ClusterIP  ·  port: 8000"]

            subgraph GW_DEP["Deployment: device-mcp-gateway  (stateless — scale freely)"]
                CTRL["FastAPI Control Plane  :8000\n─────────────────────────────────────\nPOST  /devices          register device\nGET   /devices/{n}/sse  open MCP stream\nPOST  /devices/{n}/messages  invoke tool\nGET   /health  ·  GET  /readyz  ·  GET  /metrics/summary\nProm /metrics on :9100 (dedicated port)\nRate limiting  ·  CORS  ·  X-Request-Id"]
            end

            PDB_GW["PodDisruptionBudget\ndevice-mcp-gateway-pdb\nminAvailable: 1"]
            PDB_WK["PodDisruptionBudget\ndevice-mcp-worker-pdb\nminAvailable: 1"]

            subgraph REDIS_SS["StatefulSet: redis"]
                REDIS["Redis 7\n─────────────────────────────────────\ndevice registry (Hash per device)\nassignment stream  device:assignments\ntool call streams  device:{n}:calls\nSSE session routing  session:{id}:results\nworker heartbeats  worker:{id}:heartbeat"]
            end
            REDIS_SVC["Service: redis\nClusterIP  ·  port: 6379"]
            REDIS_PVC[("PVC: redis-data\n/data — Redis AOF")]

            subgraph WK_DEP["Deployment: device-mcp-worker  (stateful — scale independently)"]
                WK["Worker\n─────────────────────────────────────\nconsumes  device:assignments  (XREADGROUP)\nspawns DevicePods per assigned device\nconsumes  device:{n}:calls  (one task/device)\nruns health loop with Redis SETNX lock\npublishes results to  session:{id}:results\nheartbeat → worker:{id}:heartbeat (TTL)"]
            end

            CM[/"ConfigMap: gateway-config\nconfig.yaml — server, registry (mode: distributed),\nredis, cors, auth, transport, discovery settings"/]
        end
    end

    subgraph APIS["External Device APIs  (in-cluster or remote)"]
        direction LR
        API1["Sensor API  :8080\n────────────────\nGET  /sensors/temp\nAuth: X-API-Key"]
        API2["Actuator API  :9090\n────────────────\nPOST /actuators/relay\nAuth: OAuth2 CC"]
    end

    LLM      -- "① MCP call  (SSE)" --> ING
    ING      -- "② TLS · route /devices/..." --> SVC
    SVC      -- "③ forward" --> CTRL
    CTRL     -- "④ publish assignment / tool call" --> REDIS_SVC
    REDIS_SVC --> REDIS
    REDIS    -- "⑤ XREADGROUP" --> WK
    WK       -- "⑥ HTTP + auth + circuit breaker" --> API1
    WK       -- "⑥ HTTP + auth + circuit breaker" --> API2
    WK       -- "⑦ PUBLISH result" --> REDIS
    REDIS    -- "⑧ pub/sub" --> CTRL
    CTRL     -- "⑨ SSE message event" --> LLM

    WK_DEP -. "mounts read-only" .-> CM
    GW_DEP -. "mounts read-only" .-> CM
    REDIS_SS -. "mounts read-write" .-> REDIS_PVC

    classDef external  fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef k8sinfra  fill:#fef9c3,stroke:#ca8a04,color:#713f12
    classDef appcore   fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef redisnode fill:#fde68a,stroke:#d97706,color:#78350f
    classDef worker    fill:#f3e8ff,stroke:#9333ea,color:#581c87
    classDef storage   fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    classDef apinode   fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e
    classDef pdb       fill:#f0fdf4,stroke:#22c55e,color:#14532d

    class LLM external
    class ING,SVC,REDIS_SVC k8sinfra
    class CTRL appcore
    class REDIS redisnode
    class WK worker
    class CM,REDIS_PVC storage
    class API1,API2 apinode
    class PDB_GW,PDB_WK pdb
```

> **Response path:** The worker (⑥) calls the device API, receives the JSON body, publishes it to a Redis pub/sub channel (⑦). The gateway instance that owns the SSE session subscribes to that channel (⑧) and delivers the result as an SSE `message` event (⑨) to the LLM client.

---

## Message Flow

### Device Registration

```mermaid
sequenceDiagram
    autonumber

    actor Admin as Admin / CI Pipeline
    participant GW as Gateway
    participant REDIS as Redis
    participant WK as Worker
    participant API as Device API

    Admin->>GW: POST /devices<br/>{ hostname, base_url, auth_type, auth }
    GW->>REDIS: HSET device:{hostname}:config ...<br/>SADD devices:all {hostname}
    GW->>REDIS: XADD device:assignments<br/>{ action: "assign", hostname }
    GW-->>Admin: 200 OK { status: "registered", pod_active: false }

    Note over WK: Assignment consumer wakes
    WK->>REDIS: XREADGROUP device:assignments
    WK->>API: GET /openapi.json  (spec discovery)
    API-->>WK: OpenAPI 3.x spec
    Note over WK: SpecTranslator → McpManifest<br/>Spawn DevicePod
    WK->>REDIS: HSET device:{hostname}:config pod_active true<br/>SET device:{hostname}:manifest ...
    WK->>REDIS: XACK  (assignment consumed)
    Note over WK: Start per-device call consumer task
```

### Runtime Tool Invocation

```mermaid
sequenceDiagram
    autonumber

    participant LLM as LLM Client
    participant GW as Gateway (any replica)
    participant REDIS as Redis
    participant WK as Worker (pod owner)
    participant API as Device API

    LLM->>GW: GET /devices/sensor-api/sse
    GW->>REDIS: HSET session:{uuid} hostname gateway_id TTL
    GW-->>LLM: event: endpoint<br/>data: /devices/sensor-api/messages?session_id={uuid}
    Note over GW: Subscribe to session:{uuid}:results (pub/sub)

    LLM->>GW: POST /devices/sensor-api/messages?session_id={uuid}<br/>{ jsonrpc: "2.0", method: "tools/call", ... }
    GW->>REDIS: XADD device:sensor-api:calls<br/>{ request_id, session_id, gateway_id, message }
    GW-->>LLM: 200 OK { status: "accepted" }

    Note over WK: Call consumer task wakes
    WK->>REDIS: XREADGROUP device:sensor-api:calls
    WK->>WK: DevicePod._handle_mcp_message()
    WK->>API: GET /sensors/temperature<br/>X-API-Key: •••<br/>(circuit breaker wraps this call)
    API-->>WK: 200 OK { "temperature": 23.4 }
    WK->>REDIS: XACK  (call consumed)<br/>PUBLISH session:{uuid}:results { jsonrpc result }

    REDIS-->>GW: pub/sub message
    GW-->>LLM: event: message<br/>data: { "jsonrpc": "2.0", "result": { "content": [...] } }
```

---

## Health, Readiness, and Disruption Safety

### Gateway probes

| Probe | Path | Behaviour |
|-------|------|-----------|
| **Liveness** | `GET /health` | Returns 200 if the process is running. In distributed mode it also reports `live_workers` and flips `status` to `"degraded"` (still 200) when no worker has a live heartbeat — a signal for the UI/operators, deliberately **not** a restart trigger (SRE #7). |
| **Readiness** | `GET /readyz` | Pings Redis (`await redis.ping()`). Returns 503 if Redis is unreachable. K8s stops routing traffic until the probe passes. **Does not** gate on worker availability — a worker outage must not pull every gateway out of the LB and break read-only endpoints. |

### Worker probes

Workers have no HTTP port. The liveness probe uses `exec`:

```yaml
livenessProbe:
  exec:
    command:
      - python
      - -c
      - |
        import os, sys, redis as r
        client = r.from_url(os.environ.get("MCP_REDIS_URL", "redis://redis:6379/0"))
        key = f"worker:{os.environ.get('WORKER_ID', 'unknown')}:heartbeat"
        sys.exit(0 if client.exists(key) else 1)
  initialDelaySeconds: 60
  periodSeconds: 30
  failureThreshold: 3
```

The heartbeat key is written by the worker's internal heartbeat loop with a TTL of `2 × health_check_interval`. A missing key means the loop has stalled — K8s will restart the pod after 3 consecutive failures (90 s).

The heartbeat is **gated on consumer-loop health** (SRE #8): the loop withholds the heartbeat (and stops refreshing device-claim leases) if a critical loop — the assignment consumer, health loop, or reconciler — has crashed, or if the assignment consumer has not made progress within `2 × health_check_interval`. So a worker whose process is alive but whose consumers are wedged now fails liveness (gets restarted) **and** lets its claims lapse so the reconciler reassigns its devices, instead of looking healthy while doing nothing.

### PodDisruptionBudgets

Both gateway and worker have a PDB with `minAvailable: 1`. This prevents node drains and cluster upgrades from taking down all replicas simultaneously. Rolling updates (during which one pod is replaced at a time) proceed normally as long as `replicas ≥ 2`.

> With `replicas: 1`, the PDB will **block voluntary eviction** — no pod can be drained. Operators must scale to 0 or delete the PDB before draining a node that hosts a single-replica deployment.

### Worker graceful shutdown

`terminationGracePeriodSeconds: 120`. On SIGTERM:
1. A `preStop: sleep 5` hook runs first, giving Kubernetes time to stop routing new assignments to this worker.
2. SIGTERM fires; the worker stops accepting new work — it cancels the background loops (heartbeat, assignment consumer, health, reconciler) and the per-device call consumers, so no new tool calls are dispatched.
3. **In-flight tool calls are drained** (SRE #6): the worker waits up to `registry.shutdown_drain_timeout` (default 25 s) for active calls to finish before cancelling any stragglers, then tears down pods and deregisters from `workers:active`.

> Keep `terminationGracePeriodSeconds` comfortably above `shutdown_drain_timeout` (120 s vs 25 s here) so the drain completes before Kubernetes force-kills the pod.

---

## Redis availability & durability

In distributed mode Redis is the **single source of truth and a single point of failure** (SRE #9). It carries *all* shared state on the hot path:

- the device registry (`device:{h}:config`, `devices:all`),
- the assignment, per-device call, and **per-session result streams**,
- the shared rate limiter, device **claim leases**, and the **reconciler leader lock**.

**Failure behaviour.** If Redis is unreachable, gateways fail `GET /readyz` (Redis `PING`) and are pulled from the load balancer; workers retry their stream reads until it returns. No split-brain occurs because claims and the reconciler lock are Redis keys — when Redis is down, nothing is assigned or reassigned. Recovery is automatic once Redis is back.

**Durability.** The provided `redis.yaml` runs `--appendonly yes`, so the AOF persists the registry and every stream across a restart. Because tool-call results are now **Redis Streams** rather than fire-and-forget pub/sub (SRE #3), a clean restart **no longer loses in-flight results** — a reconnecting gateway re-reads the session's result stream from where it left off. Only writes within the last `appendfsync` window (default `everysec` → ≤ 1 s) can be lost on an unclean crash.

**Production recommendation.** The single-node StatefulSet is fine for dev and small deployments but has no failover. For production, run **Redis Sentinel** (HA with automatic failover) or **Redis Cluster**, and point `MCP_REDIS_URL` at the Sentinel/Cluster endpoint. Size the command and pub/sub connection pools (`redis.max_connections`, `redis.pubsub_max_connections`) for your gateway/worker replica count and expected concurrent SSE streams.

---

## Observability

Each gateway and worker pod exposes Prometheus metrics on a dedicated port (`:9100`, separate from the `:8000` API). The UI/BFF and operators should treat **Prometheus and the read APIs as the observability surface — not pod log files** (see "UI/BFF sourcing" below).

### Failure-mode metrics (SRE O1)

Sites that previously only logged a failure now also increment a counter, so request loss/shedding is visible in metrics:

| Metric | Type | Incremented when |
|--------|------|------------------|
| `mcp_tool_call_timeouts_total{hostname}` | counter | the gateway's F6 watcher fires — no worker set `result:{id}` before the deadline |
| `mcp_sse_messages_dropped_total{hostname}` | counter | an embedded-mode SSE client queue is full and a response is dropped |
| `mcp_dead_letter_total{hostname}` | counter | an undeliverable tool call is moved to `device:{h}:calls:dead` |
| `mcp_circuit_breaker_opens_total{hostname}` | counter | a device pod's circuit breaker rejects a call |

### Worker backlog & HPA signal (SRE #5)

`mcp_worker_pending_calls` counts **delivered-but-unacked** (in-flight) work, but the per-device concurrency cap (SRE #5) holds excess work **undelivered** in the stream, where XPENDING can't see it. `mcp_worker_undelivered_calls` exposes that never-read backlog (XINFO GROUPS lag). **Sum the two for total work waiting → the recommended worker HPA signal.**

### Fleet gauges are leader-gated (SRE O4)

`mcp_registered_devices`, `mcp_active_pods`, and `mcp_reachable_devices` are fleet-wide. To avoid every gateway replica running a full `list_devices()` each cycle (×replicas Redis load), only the replica holding the `gateway:gauge-leader` lock computes them. **Consequence:** these gauges are populated on one replica at a time — aggregate them with `max()` across replicas in Prometheus. (Embedded mode is a single process and always refreshes.) The `/admin/overview` read aggregate is likewise served from a short-TTL per-replica cache with an `ETag` (`gateway.read_cache_ttl`, default 5 s) so a polling UI doesn't trigger a fresh `list_devices()` per request.

### End-to-end tracing (SRE O2)

The gateway assigns each request an `X-Request-Id` (generated if absent) and logs it as `rid`. That `rid` is now propagated as a field on the tool-call stream and bound into the **worker's** audit log lines, so a single id traces a call across the gateway→worker hop. Filter logs in both pods by `rid=<value>` to follow one invocation end to end.

### Per-call latency: Prometheus, not logs (SRE O3)

In distributed mode tool calls execute on the worker, so the **gateway's** audit log carries no `duration_ms` for them — that field is emitted by the gateway only in embedded mode. The worker does log `duration_ms`, but in a separate pod a gateway sidecar cannot read. The mode-independent source of per-call latency is the worker's Prometheus histogram **`mcp_tool_call_duration_seconds{hostname}`**. **Contract for the UI/BFF:** source distributed-mode latency from Prometheus (e.g. `histogram_quantile` over `mcp_tool_call_duration_seconds_bucket`), not from gateway logs.

### UI/BFF log sourcing (SRE O5)

If the UI runs as a gateway-pod sidecar, do **not** make it depend on tailing `logs/gateway.log`: that file rotates (50 MB × 5) and, more importantly, **worker logs — tool execution, latency, dead-letters — live in a different pod the sidecar cannot see**. The supported sourcing model is:

- **Metrics** (RED, failure-mode counters, latency histogram) from each pod's `:9100` Prometheus endpoint, aggregated by a Prometheus server;
- **Fleet/device state** from the gateway read APIs (`GET /admin/overview`, `GET /metrics/summary`, `GET /devices`);
- **Structured logs**, if needed, shipped from *all* pods (gateway and worker) to a central log store and queried by `rid` — never read from one pod's local file.

---

## Kubernetes Resource Summary

| Kind | Name | Purpose |
|------|------|---------|
| `Namespace` | `mcp-gateway` | Isolates all resources |
| `ConfigMap` | `gateway-config` | Non-secret `config.yaml` (mode: distributed, Redis URL, registry settings) |
| `Secret` | `gateway-secrets` | `api-key`, `secret-key`, `redis-password`, `redis-url` — injected as env vars; **never in ConfigMap**. Distributed mode requires the api-key (F-23) and an authenticated `redis-url` (F-24). |
| `StatefulSet` | `redis` | Single Redis 7 instance with AOF persistence |
| `Service` | `redis` | ClusterIP on port 6379; accessible to gateway and worker pods |
| `PersistentVolumeClaim` | `redis-data` | Persists Redis AOF data across pod restarts |
| `Deployment` | `device-mcp-gateway` | Stateless gateway — scale freely; readiness on `/readyz` |
| `Deployment` | `device-mcp-worker` | Stateful workers — scale independently; liveness via Redis heartbeat key |
| `Service` | `device-mcp-gateway` | ClusterIP on port 8000; target of the Ingress |
| `Ingress` | `device-mcp-gateway` | External HTTPS entry; TLS termination |
| `NetworkPolicy` | `device-mcp-gateway` | Restricts ingress to port 8000 |
| `PodDisruptionBudget` | `device-mcp-gateway-pdb` | `minAvailable: 1` for gateway |
| `PodDisruptionBudget` | `device-mcp-worker-pdb` | `minAvailable: 1` for worker |
| `PersistentVolumeClaim` | `gateway-data` | **Optional.** Embedded-mode only — SQLite persistence for gateway pod. Not applied by default. |

---

## Sample Device Registrations

Register the two devices shown in the diagrams after the gateway is running. Replace `mcp-gateway.example.com` with your actual hostname.

**Sensor API** — API key authentication:
```bash
curl -X POST https://mcp-gateway.example.com/devices \
  -H "Authorization: Bearer <gateway-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname":   "sensor-api",
    "base_url":   "http://sensor-svc:8080",
    "transport":  "sse",
    "auth_type":  "api_key",
    "auth": { "api_key": "sensor-key-123", "header_name": "X-API-Key" }
  }'
```

**Actuator API** — OAuth2 client credentials:
```bash
curl -X POST https://mcp-gateway.example.com/devices \
  -H "Authorization: Bearer <gateway-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname":  "actuator-api",
    "base_url":  "http://actuator-svc:9090",
    "transport": "sse",
    "auth_type": "oauth2",
    "auth": {
      "token_endpoint": "https://auth.example.com/token",
      "client_id":      "actuator-client",
      "client_secret":  "secret",
      "scopes":         ["actuators:read", "actuators:write"]
    }
  }'
```

In distributed mode, the gateway immediately returns `{ pod_active: false }` — the pod becomes active asynchronously as a worker picks up the assignment. Poll `GET /devices/{hostname}` until `pod_active: true`.

---

## Deploying with the Provided Manifests

```bash
# 1. Customise before deploying
#    deploy/kubernetes/ingress.yaml       — replace mcp-gateway.example.com
#    deploy/kubernetes/deployment.yaml    — replace device-mcp-gateway:latest with your image
#    deploy/kubernetes/worker-deployment.yaml — adjust replicas and resources

# 2. Create namespace and secrets
#    Distributed mode REQUIRES an API key (else the gateway refuses to start — Tier-0 F-23)
#    and an authenticated Redis (redis-password + a redis-url that carries it — Tier-0 F-24).
kubectl create namespace mcp-gateway
REDIS_PW=$(openssl rand -hex 24)
kubectl create secret generic gateway-secrets \
  --namespace=mcp-gateway \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --from-literal=secret-key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
  --from-literal=redis-password="$REDIS_PW" \
  --from-literal=redis-url="redis://:$REDIS_PW@redis:6379/0"   # use rediss:// when Redis terminates TLS

# 3. Deploy everything
kubectl apply -k deploy/kubernetes/

# 4. Watch rollouts
kubectl rollout status deployment/device-mcp-gateway -n mcp-gateway
kubectl rollout status deployment/device-mcp-worker -n mcp-gateway

# 5. Scale
kubectl scale deployment device-mcp-gateway --replicas=3 -n mcp-gateway
kubectl scale deployment device-mcp-worker --replicas=3 -n mcp-gateway
```

### Kustomize overlays (optional)

Create environment-specific overlays to patch image tags, resource limits, or replica counts without modifying the base manifests:

```
deploy/
  kubernetes/
    base/        ← move current files here when using overlays
    overlays/
      staging/
        kustomization.yaml   # patches image tag, sets lower limits
      production/
        kustomization.yaml   # patches image tag, sets production limits, HPA
```
