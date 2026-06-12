# Audit Logging & Data Handling

How the gateway records *who did what* and how it treats sensitive data in logs.
Relevant to SOC 2 (CC-series) and HIPAA (§164.312(b) audit controls).

## Audit events

Audit records are emitted on the normal log stream with the structured field
`event="audit"` (so a log pipeline can filter `event=audit` and forward them to a
separate, retained sink). Schema:

| Field | Meaning |
|-------|---------|
| `event` | always `"audit"` |
| `action` | dotted verb — `device.create`, `device.update`, `device.delete`, `auth.authenticate`, `authz.check`, `tool dispatch` |
| `subject` | the principal — e.g. `key:admin`, or `unauthenticated` |
| `rid` | request id; matches the access-log line and the `X-Request-Id` response header |
| `target` | what was acted on — a hostname, or `METHOD /path` |
| `outcome` | `success` \| `denied` \| `error` |
| (extra) | e.g. `reason=missing_scope:devices:write` |

### What is audited

| Action | When |
|--------|------|
| `device.create` / `device.update` / `device.delete` | a privileged `POST` / `PUT` / `DELETE /devices…` succeeds |
| `auth.authenticate` (`denied`) | a request fails authentication (**401**) |
| `authz.check` (`denied`) | an authenticated caller lacks the required scope (**403**) |
| `tool dispatch` | a tool call executes (gateway embedded dispatch / worker) |

Auth-failure auditing is centralized at the RBAC dependency seam
([`rbac.py`](../device_mcp_gateway/rbac.py)), so every protected route is covered
without per-route code.

## Access-log attribution

Every request's access-log line is bound to the resolved principal: `subject` and
`auth_method` (plus `rid`). Public routes (`/health`, `/ready`) log `subject="-"`.
This lets you attribute *any* API access to an actor, not just tool dispatch.

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
gateway, and forwarding the `event="audit"` stream to a retained, tamper-evident
sink (see findings F-57/F-58 for the roadmap on a forwarded, time-retained audit
stream).
