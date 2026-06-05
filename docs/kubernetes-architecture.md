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
                CTRL["FastAPI Control Plane  :8000\n─────────────────────────────────────\nPOST  /devices          register device\nGET   /devices/{n}/sse  open MCP stream\nPOST  /devices/{n}/messages  invoke tool\nGET   /health  ·  GET  /readyz  ·  GET  /metrics\nRate limiting (slowapi)  ·  CORS  ·  X-Request-Id"]
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
| **Liveness** | `GET /health` | Returns 200 unconditionally if the process is running. K8s restarts on failure. |
| **Readiness** | `GET /readyz` | Pings Redis (`await redis.ping()`). Returns 503 if Redis is unreachable. K8s stops routing traffic until the probe passes. |

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

### PodDisruptionBudgets

Both gateway and worker have a PDB with `minAvailable: 1`. This prevents node drains and cluster upgrades from taking down all replicas simultaneously. Rolling updates (during which one pod is replaced at a time) proceed normally as long as `replicas ≥ 2`.

> With `replicas: 1`, the PDB will **block voluntary eviction** — no pod can be drained. Operators must scale to 0 or delete the PDB before draining a node that hosts a single-replica deployment.

### Worker graceful shutdown

`terminationGracePeriodSeconds: 120`. On SIGTERM:
1. A `preStop: sleep 5` hook runs first, giving Kubernetes time to stop routing new assignments to this worker.
2. SIGTERM fires; the worker cancels its heartbeat, assignment consumer, and health loop.
3. In-flight tool calls are cancelled after the grace period expires.

> Future improvement: the shutdown handler should drain `_call_tasks` (wait for in-flight httpx calls to complete) before cancelling them, reducing the chance of mid-call interruption.

---

## Kubernetes Resource Summary

| Kind | Name | Purpose |
|------|------|---------|
| `Namespace` | `mcp-gateway` | Isolates all resources |
| `ConfigMap` | `gateway-config` | Non-secret `config.yaml` (mode: distributed, Redis URL, registry settings) |
| `Secret` | `gateway-secrets` | `api-key` and `secret-key` — injected as env vars; **never in ConfigMap** |
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
kubectl create namespace mcp-gateway
kubectl create secret generic gateway-secrets \
  --namespace=mcp-gateway \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --from-literal=secret-key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

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
