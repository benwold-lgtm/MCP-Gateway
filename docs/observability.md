# MCP Gateway — Observability Guide

This document covers the gateway's log format, the fields available for querying, and
ready-to-use configuration snippets for Grafana Loki, Splunk, and Elasticsearch.

---

## Log Architecture

The gateway uses two log sinks:

| Sink | Format | Purpose |
|------|--------|---------|
| **stderr** | Human-readable colored text | Interactive consoles, `kubectl logs`, local dev |
| **File** (`logs/gateway.log`) | Newline-delimited JSON (default) | External collectors — Fluent Bit, Promtail, Splunk UF |

Both sinks run simultaneously. The file format is controlled by `logging.json_logs` in
`config.yaml` (default: `true`). Setting it to `false` switches the file to plain text
for local development without a collector.

In Kubernetes, the recommended pattern is to mount `logs/` as an `emptyDir` volume shared
with a Fluent Bit or Promtail sidecar. See the [Kubernetes section](#kubernetes) below.

---

## Log Record Format

Each JSON log record is one line:

```json
{
  "text": "2026-06-05T12:34:56.123456+00:00 | INFO | device_mcp_gateway.main:log_requests:212 - GET /health -> 200 (1.2ms) rid=f3a8b1c2",
  "record": {
    "elapsed": { "repr": "0:00:01.234567", "seconds": 1.234567 },
    "exception": null,
    "extra": {
      "event": "audit",
      "hostname": "array-1",
      "caller": "bearer:abc12345...",
      "method": "tools/call",
      "status": "ok",
      "duration_ms": 42.3,
      "rid": "f3a8b1c2-d4e5-6f78-9012-3456789abcde"
    },
    "file": { "name": "main.py", "path": "/app/device_mcp_gateway/main.py" },
    "function": "device_sse_message",
    "level": { "name": "INFO", "no": 20 },
    "line": 580,
    "message": "tool dispatch",
    "module": "main",
    "name": "device_mcp_gateway.main",
    "process": { "id": 1, "name": "MainProcess" },
    "thread": { "id": 140234567890, "name": "MainThread" },
    "time": { "repr": "2026-06-05 12:34:56.123456+00:00", "timestamp": 1748981696.123456 }
  }
}
```

All structured fields added via `logger.bind()` appear under `record.extra`.

---

## Key Fields for Querying

| Field | Path in JSON | Description |
|-------|-------------|-------------|
| `event` | `record.extra.event` | `"audit"` for tool dispatch events; absent for general logs |
| `hostname` | `record.extra.hostname` | Registered device name (e.g. `"array-1"`) |
| `caller` | `record.extra.caller` | Truncated bearer token prefix identifying the API caller |
| `method` | `record.extra.method` | MCP JSON-RPC method (e.g. `"tools/call"`, `"tools/list"`) |
| `status` | `record.extra.status` | `"ok"`, `"error"`, or `"dispatched"` (distributed mode) |
| `duration_ms` | `record.extra.duration_ms` | Tool call round-trip time in milliseconds (embedded mode only) |
| `rid` | `record.extra.rid` | Correlation ID — matches `X-Request-Id` response header |
| `level` | `record.level.name` | `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"` |
| `message` | `record.message` | Log message string |
| `time` | `record.time.timestamp` | Unix epoch timestamp (float) |

---

## Grafana + Loki

### Promtail sidecar configuration

Add a Promtail sidecar to the gateway Deployment. The sidecar tails the JSON log file
from the shared `logs` volume.

```yaml
# In your gateway Deployment spec, add a shared volume:
volumes:
  - name: gateway-logs
    emptyDir: {}

# In the gateway container, mount it:
containers:
  - name: gateway
    volumeMounts:
      - name: gateway-logs
        mountPath: /app/logs

# Add the Promtail sidecar:
  - name: promtail
    image: grafana/promtail:latest
    args:
      - -config.file=/etc/promtail/config.yaml
    volumeMounts:
      - name: gateway-logs
        mountPath: /app/logs
      - name: promtail-config
        mountPath: /etc/promtail
```

```yaml
# promtail-config ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: promtail-config
  namespace: mcp-gateway
data:
  config.yaml: |
    server:
      http_listen_port: 9080

    clients:
      - url: http://loki:3100/loki/api/v1/push

    scrape_configs:
      - job_name: mcp-gateway
        static_configs:
          - targets: [localhost]
            labels:
              job: mcp-gateway
              namespace: mcp-gateway
              __path__: /app/logs/gateway.log

        pipeline_stages:
          - json:
              expressions:
                level: record.level.name
                message: record.message
                event: record.extra.event
                hostname: record.extra.hostname
                caller: record.extra.caller
                method: record.extra.method
                status: record.extra.status
                duration_ms: record.extra.duration_ms
                rid: record.extra.rid
                ts: record.time.timestamp

          - labels:
              level:
              event:
              hostname:

          - timestamp:
              source: ts
              format: Unix
```

### Grafana LogQL queries

```logql
# All audit events
{job="mcp-gateway"} | json | event="audit"

# Audit events for a specific device
{job="mcp-gateway"} | json | event="audit" | hostname="array-1"

# Failed tool calls
{job="mcp-gateway"} | json | event="audit" | status="error"

# Slow tool calls (> 500 ms) — embedded mode only
{job="mcp-gateway"} | json | event="audit" | duration_ms > 500

# All errors and warnings
{job="mcp-gateway"} | json | level=~"WARNING|ERROR"

# Trace a single request end-to-end by correlation ID
{job="mcp-gateway"} | json | rid="f3a8b1c2-d4e5-6f78-9012-3456789abcde"
```

---

## Splunk

### Universal Forwarder inputs.conf

If running outside Kubernetes, configure the Splunk Universal Forwarder to tail the log file:

```ini
[monitor:///app/logs/gateway.log]
index = mcp_gateway
sourcetype = _json
```

### Splunk HTTP Event Collector (HEC) — Fluent Bit

For Kubernetes, use Fluent Bit with the Splunk HEC output plugin:

```ini
[INPUT]
    Name              tail
    Path              /app/logs/gateway.log
    Parser            json
    Tag               mcp.gateway
    Refresh_Interval  5
    Mem_Buf_Limit     5MB

[OUTPUT]
    Name              splunk
    Match             mcp.*
    Host              splunk.example.com
    Port              8088
    Splunk_Token      <your-hec-token>
    Splunk_Send_Raw   off
    TLS               on
    TLS.Verify        on
```

### Splunk search queries (SPL)

```spl
# All audit events
index=mcp_gateway sourcetype=_json record.extra.event="audit"

# Audit events by device
index=mcp_gateway sourcetype=_json record.extra.event="audit" record.extra.hostname="array-1"

# Error rate per device (last 1 hour)
index=mcp_gateway sourcetype=_json record.extra.event="audit"
| eval status=spath(_raw, "record.extra.status")
| eval hostname=spath(_raw, "record.extra.hostname")
| stats count by hostname, status

# Average tool call duration per device
index=mcp_gateway sourcetype=_json record.extra.event="audit"
| eval duration=spath(_raw, "record.extra.duration_ms")
| eval hostname=spath(_raw, "record.extra.hostname")
| stats avg(duration) as avg_ms by hostname

# Trace a correlation ID
index=mcp_gateway sourcetype=_json record.extra.rid="f3a8b1c2-d4e5-6f78-9012-3456789abcde"
```

---

## Elasticsearch + Kibana

### Fluent Bit → Elasticsearch

```ini
[INPUT]
    Name              tail
    Path              /app/logs/gateway.log
    Parser            json
    Tag               mcp.gateway

[OUTPUT]
    Name              es
    Match             mcp.*
    Host              elasticsearch.example.com
    Port              9200
    Index             mcp-gateway
    Type              _doc
    Suppress_Type_Name on
    TLS               on
```

### Kibana queries (KQL)

```
# All audit events
record.extra.event : "audit"

# Failed tool calls on a specific device
record.extra.event : "audit" AND record.extra.hostname : "array-1" AND record.extra.status : "error"

# Trace by correlation ID
record.extra.rid : "f3a8b1c2-d4e5-6f78-9012-3456789abcde"
```

---

## Kubernetes

The recommended Kubernetes pattern is a Fluent Bit DaemonSet that reads container logs
from `/var/log/containers/` (captured automatically from stdout/stderr by the container
runtime). Since the gateway also writes a JSON file to `logs/`, you can use either path.

### DaemonSet approach (no sidecar needed)

Fluent Bit's Kubernetes filter automatically enriches log lines with pod name, namespace,
and container metadata. Configure an `[INPUT]` pointing to container logs and an
`[OUTPUT]` to your chosen backend (Loki, Splunk, Elastic, CloudWatch).

The stderr sink writes human-readable text, which will appear in `kubectl logs` for
operator convenience. The JSON file sink is the source for machine-readable ingestion.

### Useful kubectl commands

```bash
# Tail human-readable logs from all gateway pods
kubectl logs -f -l app=device-mcp-gateway -n mcp-gateway

# Filter audit events from a running pod (requires jq)
kubectl logs -l app=device-mcp-gateway -n mcp-gateway \
  | grep '"event": "audit"' \
  | jq '{time: .record.time.repr, hostname: .record.extra.hostname, method: .record.extra.method, status: .record.extra.status, duration_ms: .record.extra.duration_ms}'
```

---

## Disabling JSON Logs (local dev)

Set `json_logs: false` in `config.yaml` or override at runtime:

```yaml
logging:
  level: "DEBUG"
  json_logs: false
```

The file sink will write plain text. The stderr sink is always plain text regardless of
this setting.
