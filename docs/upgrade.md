# Upgrade Guide — Device MCP Gateway

How to move a running deployment to a new version without dropping traffic or losing
data. Pairs with the [operations runbook](runbook.md) (what to do if something goes wrong
mid-upgrade) and the [ADRs](adr/) (why the compatibility rules below hold).

## Versioning & compatibility policy

The project is **`0.x`** (see `pyproject.toml`): minor releases may carry breaking
changes. Until `1.0`, **read the release notes before every upgrade** and treat each one
as potentially breaking. The compatibility surfaces that matter for a live upgrade:

| Surface | Stability | Notes |
|---------|-----------|-------|
| HTTP/MCP API (`/v1/devices…`, SSE) | stable within a minor | additive changes preferred; breaking changes called out in release notes |
| Redis data model (streams, registry keys, lease keys) | **mixed-version safe within a minor** — see below | the call-stream entry is forward/back-compatible by design |
| Config schema (`config.yaml`) | additive; unknown keys **warn, don't fail** (F-50) | a new required gate is the exception — see [breaking gates](#breaking-configuration-gates) |
| Encrypted-credential format (Fernet/MultiFernet) | stable | key rotation is orthogonal — see [secret-rotation.md](secret-rotation.md) |
| Embedded SQLite schema | additive | back up `storage.db_path` before a minor upgrade |

### Mixed-version safety (rolling upgrades)

The distributed components are designed to run **mixed-version during a rollout**:

- The Redis **call-stream entry is tolerant in both directions**. A new producer adds
  fields (e.g. `traceparent` in 1H, `subject` in the identity-propagation change) that an
  old consumer ignores; an old producer omits them and a new consumer falls back to a
  default (`subject="-"`) rather than erroring. So a new gateway can feed an old worker and
  vice versa for the duration of a roll.
- Workers are **single-owner per device** (D-2) and coordinate via Redis leases, not via
  each other — a new and an old worker can hold different devices simultaneously.

This is what makes the [rolling procedure](#rolling-upgrade-distributed-mode) safe. If a
specific release breaks mixed-version operation, its notes will say so and require a
different sequence.

---

## Pre-upgrade checklist

1. **Read the release notes** for every version between current and target.
2. **Back up the durable state:**
   - Distributed: snapshot Redis (the registry + leases); the credential ciphertext lives
     here.
   - Embedded: copy `storage.db_path` (SQLite).
   - **Back up `MCP_SECRET_KEY` out-of-band** if you haven't — losing it orphans every
     stored credential.
3. **Validate the new config against the new version** before rolling:
   ```bash
   device-mcp --config config.yaml --check-config   # loads + validates, does not serve
   ```
   Fix anything the F-50 validator flags (it warns on unknown/misplaced keys with a dotted
   path). Confirm the [breaking gates](#breaking-configuration-gates) are satisfied.
4. **Confirm headroom:** the roll briefly removes a replica from rotation. Ensure the PDB
   `minAvailable` and current replica count leave you serving.
5. **Note your current image tag** for a fast [rollback](#rollback).

---

## Rolling upgrade (distributed mode)

Because the fleet is mixed-version safe, a standard Kubernetes rolling update works. Do it
**one deployment at a time** so you can stop on the first sign of trouble:

```bash
# 1. Workers first — they own the device connections; a roll rebalances devices (F-07).
kubectl -n mcp set image deploy/device-mcp-worker worker=<registry>/device-mcp-worker:<tag>
kubectl -n mcp rollout status deploy/device-mcp-worker

# 2. Then the gateway — stateless; losing a replica only drops its in-flight SSE streams,
#    which clients reconnect and retry (F-20).
kubectl -n mcp set image deploy/device-mcp-gateway gateway=<registry>/device-mcp-gateway:<tag>
kubectl -n mcp rollout status deploy/device-mcp-gateway
```

Between the two steps, sanity-check the [post-upgrade verification](#post-upgrade-verification).
Workers-first means new execution logic lands before the new dispatch logic that may rely
on it; if a release's notes prescribe the opposite order, follow the notes.

### Watch during the roll

- `mcp_worker_pods` — devices redistribute as pods cycle; transient skew is normal (the
  rebalance, F-07, converges it).
- `MCPDeadLetterGrowing` — pod-replace windows can dead-letter a few "no active pod" calls;
  [replay them](runbook.md#work-the-dead-letter-queue) once the roll settles.
- `MCPReconcilerReassignmentChurn` — brief churn during the roll is expected; sustained
  churn after it settles is a problem (see the runbook).

---

## Breaking configuration gates

Distributed mode **fails closed** (ADR-0006). When upgrading *into* a version that adds or
tightens a gate, the new process **refuses to start** until config satisfies it — this is
intentional, and the reason to validate config first:

| Gate | Requirement | Escape hatch (lab only) |
|------|-------------|-------------------------|
| **F-23** API key | distributed mode needs at least one API key | `gateway.allow_anonymous: true` |
| **F-24** Redis auth | the Redis URL must carry a password | `redis.allow_insecure: true` |

If an upgrade surfaces one of these for the first time, set the **real** control (an API
key, an authenticated Redis URL) — not the escape hatch. The hatches exist for local
development; using them to clear an upgrade blocker re-opens a release-blocking
vulnerability. The [runbook](runbook.md#the-gateway-or-worker-wont-start-r2) covers the
exact refusal messages.

---

## Embedded mode

Single process, single SQLite file — there is no rolling story:

1. Back up `storage.db_path`.
2. Stop the process, deploy the new version, validate config (`--check-config`), start it.
3. Schema changes are additive; the backup is your rollback.

Embedded mode keeps its documented single-operator fail-open defaults (warned, not gated)
— no API-key/Redis gate applies.

---

## Secret-key rotation vs. version upgrade

These are **independent** and should not be combined in one change window. Rotating
`MCP_SECRET_KEY` follows its own zero-downtime, multi-key flow in
[secret-rotation.md](secret-rotation.md) (deploy both keys → run `device-mcp-rotate-secrets`
→ retire the old key). Do a version upgrade and a key rotation as two separate, verified
steps so that if one goes wrong you know which.

---

## Post-upgrade verification

```bash
# Liveness / readiness on each component
curl -fsS "$GW/livez" && curl -fsS "$GW/readyz"

# Workers present and devices owned
curl -s "$GW/metrics" | grep -E 'mcp_worker_pods|mcp_reconciler_leader'

# A representative tool call end-to-end (pick a known-good device + tool)
#   then grep its rid through the access log to confirm gateway→worker flow.

# Audit chain still intact across the restart (F-57)
python -m device_mcp_gateway.audit_verify logs/audit.log
```

Confirm no unexpected `MCPDeviceToolsBreakingChange` (an upgrade shouldn't change a
device's *upstream* spec), no sustained `MCPReconcilerReassignmentChurn`, and that the
error-budget burn alerts are quiet.

---

## Rollback

Mixed-version safety cuts both ways — rolling **back** is the same procedure with the old
tag:

```bash
kubectl -n mcp rollout undo deploy/device-mcp-gateway
kubectl -n mcp rollout undo deploy/device-mcp-worker
```

Caveats:

- **Config gates:** if you rolled back because a new gate blocked startup, the rollback
  removes the requirement — but fix the config so the next attempt succeeds rather than
  staying on the old version.
- **Data:** Redis/SQLite state written by the new version is read by the old version under
  the same back-compatible rules (new fields are ignored). If a release's notes flag a
  one-way data migration, restore from the pre-upgrade backup instead of rolling code back.
- **Secret keys:** a rollback does **not** undo a completed key rotation — the new key
  stays primary. Keep both keys configured until you're settled on a version.
