# Audit Logging & Data Handling

How the gateway records *who did what* and how it treats sensitive data in logs.
Relevant to SOC 2 (CC-series) and HIPAA (§164.312(b) audit controls).

## Audit events

Audit records are emitted with the structured field `event="audit"`. They appear on
the normal log stream **and** on a dedicated, always-JSON audit sink
(`logging.audit_file`, default `logs/audit.log`) that carries only audit records —
the clean stream to forward to a retained SIEM/WORM store. Schema:

| Field | Meaning |
|-------|---------|
| `event` | always `"audit"` |
| `action` | dotted verb — `device.create`, `device.update`, `device.delete`, `auth.authenticate`, `authz.check`, `tool dispatch` |
| `subject` | the principal — e.g. `key:admin`, or `unauthenticated` |
| `rid` | request id; matches the access-log line and the `X-Request-Id` response header |
| `target` | what was acted on — a hostname, or `METHOD /path` |
| `outcome` | `success` \| `denied` \| `error` |
| `audit_seq` / `audit_prev` / `audit_hash` | tamper-evident hash-chain fields (see below) |
| (extra) | e.g. `reason=missing_scope:devices:write` |

### What is audited

| Action | When |
|--------|------|
| `device.create` / `device.update` / `device.delete` | a privileged `POST` / `PUT` / `DELETE /v1/devices…` succeeds |
| `auth.authenticate` (`denied`) | a request fails authentication (**401**) |
| `authz.check` (`denied`) | an authenticated caller lacks the required scope (**403**) |
| `tool dispatch` | a tool call executes (gateway embedded dispatch / worker) |

Auth-failure auditing is centralized at the RBAC dependency seam
([`rbac.py`](../device_mcp_gateway/rbac.py)), so every protected route is covered
without per-route code.

## Tamper-evidence (F-57)

Each audit record is linked into an append-only **hash chain**: `audit_hash =
sha256(audit_seq ‖ audit_prev ‖ canonical(payload))`, where `audit_prev` is the
previous record's hash. Editing a record changes its hash; deleting or reordering
one breaks the `audit_prev` linkage of the next. The chain continues across a
process restart (it is re-seeded from the tail of the existing audit file) and is
per-process — the gateway and each worker keep their own files
(`logs/audit.log`, `logs/worker-audit.log`) so independent chains never interleave.

Verify a file offline:

```bash
python -m device_mcp_gateway.audit_verify logs/audit.log
# OK: verified 1234 audit record(s)            → exit 0
# FAIL: hash mismatch at seq 42: record was altered → exit 1
```

To verify across a rotation boundary, pass the prior file's last hash and next seq:
`--start-prev <hash> --start-seq <n>`. In-app chaining detects local tampering; for
end-to-end assurance, **forward the audit stream to an append-only sink** (the SIEM
holds an independent copy, so even wholesale local-file replacement is caught).

## Retention, legal hold & disposal (F-58)

The dedicated audit sink uses **time-based retention** (`logging.audit_retention`,
default `"90 days"`) rather than a backup-file count, so retention maps to a policy
period. Set it to your regulatory window (e.g. `"7 years"` for HIPAA-aligned
retention).

- **Disposal:** files past `audit_retention` are deleted automatically by the sink.
  Choose the value to match your documented disposal schedule.
- **Legal hold:** to suspend disposal, raise `audit_retention` (or forward the stream
  to a sink with hold capability and stop relying on local deletion). Because the
  primary retained copy should live in the SIEM/WORM store, legal hold is enforced
  there; the local file is a forwarding buffer.
- **Disable:** set `logging.audit_enabled: false` to drop the dedicated sink (records
  still appear in the main log).

## Access-log attribution

Every request's access-log line is bound to the resolved principal: `subject` and
`auth_method` (plus `rid`). Public routes (`/health`, `/ready`) log `subject="-"`.
This lets you attribute *any* API access to an actor, not just tool dispatch.

## Attribution across the device hop (ADR-0026)

The audit record above names the **person or agent** that made the request. The device's own
log names the **service account** the gateway used to reach it — one account per device, the
same one for every user of the tenant. [ADR-0026](adr/0026-service-identity-per-device.md)
accepts that permanently, so answering "which person caused this change on the appliance?"
means joining the two logs.

The join key is the request id. The gateway puts it in three places for one call:

| Where | Field |
|---|---|
| The caller's response | `X-Request-Id` header |
| The gateway's access log and audit record | `rid` |
| **The outbound call to the device** | `X-Request-Id` header |

The third row is the one that makes the join possible, and it is a **requirement**, not a
diagnostic nicety — it is the compensating control for the device seeing one identity. It is
stamped at the guarded-egress seam, so it covers tool calls, resource reads and MCP-passthrough
hops alike; it cannot be chosen by a tool argument; and it is omitted rather than invented when
there is no request in scope (an id minted at the wire would join to nothing).

To trace one call end to end:

```
# 1. the gateway's side — who asked, and was it allowed
jq 'select(.record.extra.rid == "<id>")' logs/audit.log

# 2. the device's side — what actually happened there
#    (however that appliance exposes its log; match on the same <id>)
```

### Device-onboarding check

Whether a device **records** inbound headers is a property of that device, not something the
gateway can promise. Before a device is trusted with writes, verify it:

1. Invoke any tool on the device through the gateway and note the `X-Request-Id` from the
   response.
2. Find that same value in the device's own request/audit log.

If it is absent, the device discards the header and the join falls back to timestamp plus
service account — weaker, and worth recording as a known property of that device rather than
discovering during an investigation.

## Credential redaction in logs

A device `base_url` / `spec_url` may embed credentials (`https://user:pass@host`).
Before any URL is logged it passes through `redact_url()`, which replaces the
userinfo with `***@` — so credentials never reach the logs. Tool **arguments and
request bodies are not logged** at all.

## Data-handling note for operators

The gateway is a **data conduit**: tool results are arbitrary upstream data and may
contain PII/PHI. That data flows **through** to the MCP client; it is **not logged or
persisted** by the gateway. What the gateway stores/logs:

| Data | Stored? | Logged? |
|------|---------|---------|
| Device `base_url`/`spec_url` | yes (registry/SQLite) | yes, **credential-redacted** |
| Device credentials (API keys, OAuth secrets) | yes, **encrypted** (Fernet) when `secret_key` set | no |
| Tool arguments / request bodies | no | no |
| Tool results (may carry PII/PHI) | no | no |
| Principal subject + action (audit) | no | yes (audit events) |

For regulated deployments, operators remain responsible for: classifying the data
their devices expose, deciding whether tool I/O may be logged downstream of the
gateway, and **forwarding the dedicated audit file to a retained, append-only sink**.
The gateway makes that stream tamper-evident (hash chain, F-57) and time-retained
(F-58); the durable, hold-capable copy of record lives in the operator's SIEM/WORM
store.
