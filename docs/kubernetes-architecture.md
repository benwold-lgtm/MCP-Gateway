# MCP Gateway — Kubernetes Deployment Architecture

This document describes how the **hermeshome Device MCP Gateway** is deployed on Kubernetes and traces the complete message path from an LLM client through the gateway to downstream device APIs.

The two sample devices used throughout — a **Sensor API** and an **Actuator API** — represent the most common patterns: a read-only telemetry endpoint and a command/control endpoint.

---

## Deployment Overview

The diagram below shows every Kubernetes object, the internal application components running inside the gateway pod, and the two external device APIs. Numbered arrows trace the forward request path; responses follow the same path in reverse.

```mermaid
flowchart TB
    LLM[/"LLM Client\nClaude Desktop · Cursor · API Application"/]

    subgraph CLUSTER["Kubernetes Cluster"]
        subgraph NS["Namespace: mcp-gateway"]

            ING["Ingress\nnginx.ingress.kubernetes.io\nHost: mcp-gateway.example.com\nTLS termination"]

            SVC["Service: device-mcp-gateway\ntype: ClusterIP  ·  port: 8000"]

            subgraph DEP["Deployment: device-mcp-gateway  (replicas: 1)"]

                CTRL["FastAPI Control Plane  :8000\n─────────────────────────────────────\nPOST  /devices               register device\nGET   /devices/{name}/sse    open MCP stream\nPOST  /devices/{name}/messages  invoke tool\nGET   /health  ·  GET  /metrics"]

                REG["Registry  +  SpecCache\n─────────────────────────────────────\nReloads registrations from SQLite on startup\nHealth loop: 30 s  ·  Spec cache TTL: 1 h\nMax concurrent device pods: 50"]

                subgraph DPODS["Device Pods  (one FastMCP server per registered device)"]
                    direction LR
                    DP1["DevicePod: sensor-api\nFastMCP\n─────────────────────\ntool · get_temperature\ntool · list_sensors"]
                    DP2["DevicePod: actuator-api\nFastMCP\n─────────────────────\ntool · set_relay_state\ntool · get_relay_status"]
                end

                CTRL -- "lookup + dispatch" --> REG
                REG -. "spawn / teardown" .-> DP1
                REG -. "spawn / teardown" .-> DP2
            end

            CM[/"ConfigMap: gateway-config\nconfig.yaml — server, registry,\nauth, transport, discovery settings"/]
            PVC[("PVC: gateway-data\n/app/data/devices.db\nRegistered devices")]
        end
    end

    subgraph APIS["External Device APIs  (in-cluster services or remote hosts)"]
        direction LR
        API1["Sensor API  :8080\n──────────────────────────────\nGET  /api/v1/sensors/temperature\nGET  /api/v1/sensors\nAuth: X-API-Key header"]
        API2["Actuator API  :9090\n──────────────────────────────\nPOST /api/v1/actuators/relay\nGET  /api/v1/actuators/relay/status\nAuth: OAuth2 client credentials"]
    end

    LLM          -- "① MCP call  (SSE)" --> ING
    ING          -- "② TLS · route /devices/..." --> SVC
    SVC          -- "③ forward" --> CTRL
    CTRL         -- "④ route tool call to pod" --> DP1
    CTRL         -- "④ route tool call to pod" --> DP2
    DP1          -- "⑤ HTTP GET + auth headers" --> API1
    DP2          -- "⑤ HTTP POST + auth headers" --> API2

    DEP -. "mounts read-only" .-> CM
    DEP -. "mounts read-write" .-> PVC

    classDef external  fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef k8sinfra  fill:#fef9c3,stroke:#ca8a04,color:#713f12
    classDef appcore   fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef devpod    fill:#f3e8ff,stroke:#9333ea,color:#581c87
    classDef storage   fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    classDef apinode   fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e

    class LLM external
    class ING,SVC k8sinfra
    class CTRL,REG appcore
    class DP1,DP2 devpod
    class CM,PVC storage
    class API1,API2 apinode
```

> **Response path:** ⑥ JSON body returns from the device API → ⑦ DevicePod wraps it as an MCP tool result → ⑧ Gateway delivers it to the LLM client as an SSE event over the open stream established in step ①.

---

## Message Flow

The sequence diagram below covers two phases:

- **Device Registration** — a one-time admin operation that teaches the gateway about each API.
- **Runtime Tool Invocation** — the repeated LLM-driven call cycle at inference time.

```mermaid
sequenceDiagram
    autonumber

    actor Admin as Admin / CI Pipeline
    participant GW as Gateway<br/>(FastAPI :8000)
    participant REG as Registry<br/>+ DevicePod
    participant SENSOR as Sensor API<br/>:8080
    participant ACTUATOR as Actuator API<br/>:9090
    actor LLM as LLM Client

    rect rgb(254, 249, 195)
        Note over Admin,ACTUATOR: Phase 1 — Device Registration  (one-time setup per device)

        Admin->>GW: POST /devices<br/>{ hostname: "sensor-api",<br/>  base_url: "http://sensor-svc:8080",<br/>  transport: "sse",<br/>  auth_type: "api_key",<br/>  auth: { api_key: "•••", header_name: "X-API-Key" } }

        GW->>SENSOR: GET /api/v1/openapi.json<br/>(auto-discovery — tries common spec paths)
        SENSOR-->>GW: OpenAPI 3.x specification

        GW->>REG: SpecTranslator converts operations → MCP tools<br/>Spawn DevicePod: sensor-api
        REG-->>GW: pod active  tools: [get_temperature, list_sensors]
        GW-->>Admin: 200 OK  { status: "registered", pod_active: true }

        Admin->>GW: POST /devices<br/>{ hostname: "actuator-api",<br/>  base_url: "http://actuator-svc:9090",<br/>  transport: "sse",<br/>  auth_type: "oauth2",<br/>  auth: { token_endpoint: "…", client_id: "…", client_secret: "•••" } }

        GW->>ACTUATOR: GET /api/v1/openapi.json
        ACTUATOR-->>GW: OpenAPI 3.x specification

        GW->>REG: SpecTranslator converts operations → MCP tools<br/>Spawn DevicePod: actuator-api
        REG-->>GW: pod active  tools: [set_relay_state, get_relay_status]
        GW-->>Admin: 200 OK  { status: "registered", pod_active: true }
    end

    rect rgb(220, 252, 231)
        Note over LLM,SENSOR: Phase 2a — Runtime Tool Invocation  (sensor read)

        LLM->>GW: GET /devices/sensor-api/sse?client_id=abc-123
        Note right of GW: SSE stream opened<br/>keepalive ping every 15 s

        LLM->>GW: POST /devices/sensor-api/messages?client_id=abc-123<br/>{ "tool": "get_temperature",<br/>  "arguments": { "sensor_id": 1 } }

        GW->>REG: dispatch to DevicePod sensor-api
        REG->>SENSOR: GET /api/v1/sensors/temperature?sensor_id=1<br/>X-API-Key: •••
        SENSOR-->>REG: 200 OK  { "temperature": 23.4, "unit": "C",<br/>  "timestamp": "2026-06-03T10:00:00Z" }
        REG-->>GW: MCP tool result
        GW-->>LLM: SSE event<br/>{ "result": { "body": { "temperature": 23.4, "unit": "C" } } }
    end

    rect rgb(243, 232, 255)
        Note over LLM,ACTUATOR: Phase 2b — Runtime Tool Invocation  (actuator command)

        LLM->>GW: POST /devices/actuator-api/messages?client_id=abc-123<br/>{ "tool": "set_relay_state",<br/>  "arguments": { "relay_id": "relay-01", "state": "on" } }

        GW->>REG: dispatch to DevicePod actuator-api
        Note right of REG: OAuth2 token fetched<br/>and cached automatically
        REG->>ACTUATOR: POST /api/v1/actuators/relay<br/>Authorization: Bearer •••<br/>{ "relay_id": "relay-01", "state": "on" }
        ACTUATOR-->>REG: 200 OK  { "relay_id": "relay-01", "state": "on",<br/>  "acknowledged": true }
        REG-->>GW: MCP tool result
        GW-->>LLM: SSE event<br/>{ "result": { "body": { "relay_id": "relay-01", "state": "on" } } }
    end
```

---

## Kubernetes Resource Summary

| Kind | Name | Purpose |
|------|------|---------|
| `Deployment` | `device-mcp-gateway` | Gateway container (`python:3.12-slim`); single replica (see note below) |
| `Service` | `device-mcp-gateway` | ClusterIP on port 8000; target of the Ingress rule |
| `Ingress` | `device-mcp-gateway` | External HTTPS entry point; TLS termination; routes all `/devices/…` traffic |
| `ConfigMap` | `gateway-config` | Supplies `config.yaml` at `/app/config.yaml` inside the container |
| `PersistentVolumeClaim` | `gateway-data` | Persists `devices.db` at `/app/data`; device registrations survive pod restarts |

> **Single-replica constraint:** Device pods are in-process — they run as async tasks inside the gateway process. Horizontal scaling requires an external registry backend (not yet implemented). Run one replica and rely on the PVC and SQLite persistence for durability across pod restarts.

---

## Sample Device Registrations

Register the two devices shown in the diagrams after the gateway is running.

**Sensor API** — API key authentication:

```bash
curl -X POST https://mcp-gateway.example.com/devices \
  -H "Content-Type: application/json" \
  -d '{
    "hostname":   "sensor-api",
    "base_url":   "http://sensor-svc:8080",
    "transport":  "sse",
    "auth_type":  "api_key",
    "auth": {
      "api_key":     "sensor-key-123",
      "header_name": "X-API-Key"
    }
  }'
```

**Actuator API** — OAuth2 client credentials:

```bash
curl -X POST https://mcp-gateway.example.com/devices \
  -H "Content-Type: application/json" \
  -d '{
    "hostname":  "actuator-api",
    "base_url":  "http://actuator-svc:9090",
    "transport": "sse",
    "auth_type": "oauth2",
    "auth": {
      "token_endpoint": "https://auth.example.com/token",
      "client_id":      "actuator-client",
      "client_secret":  "••••",
      "scopes":         ["actuators:read", "actuators:write"]
    }
  }'
```

Once registered, point your MCP client at the SSE stream:

```
GET https://mcp-gateway.example.com/devices/sensor-api/sse
GET https://mcp-gateway.example.com/devices/actuator-api/sse
```

Both devices will be automatically reconnected if the gateway pod is restarted, as long as the `gateway-data` PVC is intact.

---

## Deploying with the Provided Manifests

All Kubernetes resources are in [`deploy/kubernetes/`](../deploy/kubernetes/). The directory is structured as a [Kustomize](https://kustomize.io/) base so you can overlay environment-specific values without editing the base files.

### Files

| File | Purpose |
|------|---------|
| `namespace.yaml` | Creates the `mcp-gateway` namespace |
| `configmap.yaml` | Supplies `config.yaml` to the container (non-secret settings only) |
| `pvc.yaml` | 10 Gi `ReadWriteOnce` volume for `devices.db` |
| `deployment.yaml` | Single-replica gateway pod; liveness + readiness on `/health` |
| `service.yaml` | ClusterIP on port 8000 |
| `ingress.yaml` | NGINX ingress with TLS stub (update host and secretName) |
| `kustomization.yaml` | Kustomize root — applies all of the above |

### Quick Start

```bash
# 1. Edit deploy/kubernetes/ingress.yaml — replace mcp-gateway.example.com with your domain
# 2. Edit deploy/kubernetes/deployment.yaml — replace device-mcp-gateway:latest with your image

# 3. Create the namespace and secrets
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl create secret generic gateway-secrets \
  --namespace=mcp-gateway \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --from-literal=secret-key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 4. Deploy everything
kubectl apply -k deploy/kubernetes/

# 5. Watch rollout
kubectl rollout status deployment/device-mcp-gateway -n mcp-gateway
```

### Overlays (optional)

Create environment-specific overlays under `deploy/kubernetes/overlays/<env>/` to patch the image tag, resource limits, or replica count without modifying the base:

```
deploy/
  kubernetes/
    base/        ← rename current files here when using overlays
    overlays/
      staging/
        kustomization.yaml   # patches image tag, sets lower limits
      production/
        kustomization.yaml   # patches image tag, sets production limits
```
