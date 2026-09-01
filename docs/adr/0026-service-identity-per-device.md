# ADR-0026: A device sees one service identity; the caller is carried by correlation, not by credentials

- **Status:** Accepted
- **Date:** 2026-09-01
- **Related:** [ADR-0007](0007-federated-identity-oidc-and-gateway-rbac.md) (Mode A relays the
  user's own token to the *gateway*; this record says where that stops),
  [ADR-0018](0018-device-credentials-by-reference.md) §1a (device credentials are
  operator-provisioned, held by reference),
  [ADR-0022](0022-agent-initiated-device-writes-are-plan-bound.md) (what narrows a *write*,
  and where that narrowing lives), [ADR-0009](0009-mcp-passthrough.md) (a remote MCP server
  is a device, so this record covers it too), [audit-logging.md](../audit-logging.md)

## Context

Identity is per-user from the browser to the gateway and stops there.

```
BSmith --OIDC token--> BFF --the same token (Mode A)--> Gateway --one device credential--> appliance
        \_________________ per-user identity _________________/        \_ one service identity _/
```

The gateway authenticates BSmith, derives scopes from the signature-verified `groups` claim,
authorizes the route, and writes a hash-chained audit record naming BSmith. It then calls the
device with the credential registered for that device. Nothing in `auth/base.py` or
`auth/api_key.py` takes a principal: **the device auth layer never sees who the caller is.**
Every user of a tenant reaches a given appliance as the same account, and the appliance's own
log says so.

This was noticed as a lab finding (LR-04) and read, initially, as a gap. It is not one, for
three reasons that were already settled elsewhere:

- `auth/oauth2.py` supports `client_credentials`, `password` and `refresh_token` — all service
  identities — and deliberately excludes `authorization_code` (needs a human at a redirect) and
  **`jwt-bearer`**, the RFC 7523 grant an on-behalf-of flow would use. That exclusion is a
  decision already taken.
- ADR-0018 §1a scoped by-reference credentials to **operator-provisioned** secrets. A credential
  minted per human per device is the thing that decision excluded.
- The gateway is an unattended process acting for agents as often as for people. There is
  frequently no human to impersonate.

Finding F-30 is marked done, and it is worth being precise about what it closed: the principal
`subject` rides the Redis stream into the worker's execution-audit records. That is
gateway→worker **audit attribution**, expressly "not an isolation gate" (D-1). The finding's
*title* describes the wider problem; its *resolution* covers the narrower one. The device hop
was never in its scope.

The independent confirmation is that the same constraint exists in comparable software:
`containers/kubernetes-mcp-server` authenticates to the Kubernetes API as a single fixed
identity per instance with no per-request impersonation, which is why this project's deployment
plan gives each tenant its own instance rather than sharing one. An appliance is shareable only
when it enforces its own per-user RBAC — and then it is doing so for its *own* console users,
not for the gateway's.

## Decision

### 1. Service identity per device is the model, and it is permanent

A device call carries the identity of the **gateway acting for a tenant**, not the identity of
the human or agent that caused it. This is the accepted architecture, not a limitation awaiting
a fix. It is not on a roadmap, it is not a known gap, and a review that reports it as one should
be answered with this record.

The gateway therefore makes **two different guarantees, and only two**:

| Question | Answered by | Where |
|---|---|---|
| Who asked for this, and was it allowed? | The principal, scopes, and the hash-chained audit record | The gateway |
| What did the gateway then do to the device? | The device credential, and the device's own log | The device |

Joining the two is the subject of §2. Collapsing them into one is not attempted.

### 2. The join is a shared correlation id, and it is a **requirement**

Because §1 is permanent, the only way to answer "which person caused this change on the
appliance?" is to put the gateway's audit record beside the device's own log and join them. That
join needs one value present on both sides.

**Every outbound hop the gateway makes on a caller's behalf MUST carry `X-Request-Id` holding
the same request id that appears in the access log, in the audit record's `rid` field, and in
the response header the caller received.** This is load-bearing: it is the compensating control
that makes §1 acceptable rather than merely tolerated. It is not a diagnostic convenience and
must not be treated as one when weighing a change that would drop it.

Four properties, each pinned by a test (`tests/test_correlation_egress.py`):

1. **One seam.** The id is stamped by a request event hook installed in
   `security.url_policy.build_guarded_client` — the same builder that installs the SSRF guard.
   A new outbound path inherits correlation by construction rather than by its author
   remembering. Tool calls, resource reads and MCP-passthrough hops all pass through it.
2. **Not caller-choosable.** The hook *assigns* the header after the request is built, so an
   OpenAPI `in: header` tool argument cannot pick the id that will identify it. `x-request-id`
   is additionally in the pod's reserved-header set — a deliberate overlap, kept because it
   names the cause at the point of the attempt.
3. **Never invented at egress.** With no request in scope the header is omitted, never
   generated. An id minted at the wire would look like a correlation id and join to nothing,
   which is worse than a visible gap. The two entry points that *do* mint one are the gateway's
   HTTP middleware and the worker's stream dispatch; the worker's binding is scoped per call so
   one caller's id can never bleed onto the next.
4. **Demonstrated end to end**, against a real gateway and a real device recording what
   arrived — not only at the unit seam. The natural unit test here (patch
   `httpx.AsyncClient.request`, inspect the headers kwarg) cannot see the id at all, because
   httpx runs request hooks inside `send()`; a suite written that way would pass against a
   build that stamps nothing.

**What the gateway cannot promise** is the other half: whether a device *records* inbound
headers is a property of that device. Verifying it is therefore a device-onboarding step —
see the device-onboarding check in [audit-logging.md](../audit-logging.md) — not an assumption. A device that discards
the header leaves the join to timestamp and account, which is weaker; that is a fact to know
about a device before it is trusted with writes, not a reason to change §1.

### 3. What narrows a call is gateway-side, and stays there

Since the device sees one identity, per-user narrowing cannot happen at the device. It happens
before the call: RBAC scopes (ADR-0007), plan-bound elevation for agent-initiated writes
(ADR-0022), the delegated support grant a provider must hold (ADR-0017). The device credential
is the *ceiling*; the gateway's authorization is the *actual* grant, and the audit records which
one was exercised.

### 4. The scope of this decision: **categorical, not narrow**

Recorded explicitly, because both halves of it are easy to re-litigate one device at a time.

**The acceptance is categorical.** It holds for every device kind the gateway speaks to —
OpenAPI-described appliances, MCP passthrough upstreams (ADR-0009), and provider-operated
services claimed from the catalog (ADR-0020) — and it holds for devices that *could*
technically accept a user token as much as for those that cannot. The narrow alternative
("accept it for Prism, revisit per device") was rejected: it would make identity semantics a
per-device property, so no statement about what an audit record means could be made about the
fleet, and every new device would reopen the question. One answer for all devices is the
property worth having.

**The credential's authority at the device is likewise categorical.** One credential per device
holds the union of what any authorized caller may do there, narrowed only gateway-side per §3.
The narrow alternative — splitting each device's credential per capability (a read credential
and a write credential, so the appliance itself constrains the gateway) — was considered and
**not adopted**: it doubles the operator's credential inventory and rotation burden for a
device-side ceiling that only bites when the gateway's own authorization has already failed,
and it does not get any closer to per-user attribution, which is the thing actually wanted.
Operators who want a lower ceiling for a particular device should provision a
lower-privileged credential for it; nothing here prevents that, and it stays their choice
rather than the gateway's model.

## Alternatives considered

1. **RFC 8693 token exchange / `jwt-bearer`** — the gateway swaps the user's token for one with
   the device's audience. Cleanest, and the only one that would scale. Requires the device to
   accept OIDC bearer tokens on its **API** (not merely its console) *and* an IdP willing to
   perform the exchange *and* the `jwt-bearer` grant that `auth/oauth2.py` deliberately
   excludes. It also has no answer for an agent-initiated call with no human behind it.
2. **Per-(user, device) stored credentials** — cuts directly against ADR-0018 §1a, and turns
   the gateway into a credential manager for the cross product of humans and devices.
3. **Impersonation header** — a service account plus "act as this user", the shape Kubernetes'
   `Impersonate-User` uses. Requires the device to support it; almost none do; and the trust it
   asks of the device is the trust the device already places in the service account, so it adds
   attribution without adding constraint.

All three are rejected **as the model**. Any of them may still be adopted for a *specific*
device that supports it, as an enhancement to that device's adapter — but per §4 that would not
change what the gateway guarantees about the fleet, and such an adapter must still emit the
correlation id.

## Consequences

- A single sign-on estate is still worth having for a tenant, and this record should not be read
  as arguing otherwise: one identity, one lifecycle, one MFA and offboarding path for a person
  across the gateway console and the appliance's own console. What it does not buy is the
  gateway's API calls running as that person. Human-at-a-console and machine-calling-an-API are
  different paths.
- "Create a VM *as BSmith*" is not achievable and will not become achievable. "Show that BSmith
  caused the call that created this VM, from two logs that agree" is, and is tested.
- An appliance that cannot enforce its own per-user RBAC should not be shared across tenants —
  give each tenant its own instance. This is why the deployment plan does exactly that for
  `kubernetes-mcp-server`.
- Dropping or renaming the outbound `X-Request-Id`, or generating one at egress, is a breaking
  change to a security property, not a logging tweak.

## What would reopen this

A single, specific fact: an IdP-mediated token exchange becoming available *and* the fleet's
devices broadly accepting OIDC bearer tokens on their APIs. That is an industry condition, not
a backlog item. Until then §1 holds, and the correlation id in §2 is how the question gets
answered.
