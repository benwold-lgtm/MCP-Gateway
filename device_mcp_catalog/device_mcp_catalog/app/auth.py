# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Two caller classes, and the tenant is read from the credential (ADR-0020 §7a).

* **Provider console** — holds one privileged catalog credential. May curate device types,
  assign and revoke assignments, and read everything.
* **A tenant's console** — holds its own credential, one per tenant. May read the device types
  assigned **to it**, and record claims **for itself**.

This replaces the single shared bearer token phase 1 shipped with. That token was correct for
the topology it was written for — one caller, the provider console's `CatalogClient` — and
`auth.py` said so in writing. What invalidated it is that the second caller already existed in
code: the tenant console's own catalog routes read this service directly, through the same
client and therefore the same token. **A documented assumption is not a guard.**

Two rules, and neither is optional:

**The tenant is read from the credential, never from the request.** A `tenant_id` in a path or
a body is a *client assertion*, and this project has settled how those are treated everywhere
it matters — ADR-0017's `provider_subject` is filled from the session's own subject, and §2's
`assigned_by` follows the same rule. `enforce_tenant_scope` is that rule for this service, and
it lives as a **router-level dependency** rather than a line in each handler on purpose: §7a's
finding was that the tenant console's own behaviour was already correct and the *enforcement
was in the wrong layer*, holding only as long as no route forgot it. A guard every route must
remember is the bug, not the fix.

**A tenant caller cannot see the unscoped catalog.** `GET /device-types` enumerates every
curated type in the estate. For a tenant caller the type list *is* the assignment list.

A mismatch is **refused, never filtered to empty and never rewritten to the caller's own
tenant** — the disagreement is the signal, and silently reinterpreting it would destroy the
only evidence that something asked for a neighbour's data.

**On "audited".** §7a says refusals are audited; this service has no audit chain of its own
(the console BFF is the audit writer, and giving a second component one was explicitly not the
plan). What exists here is a structured `WARNING` per refusal, carrying both tenants and the
route. That is weaker than the BFF's hash-chained records and is stated rather than implied.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request
from loguru import logger

#: Every request body key that names a tenant. `RecordClaim.tenant_id` is the only one today;
#: the constant exists so that adding a second is a one-line change here rather than a new
#: place for the rule to be forgotten — which is the failure mode §7a is about.
_TENANT_BODY_KEYS = ("tenant_id",)


@dataclass(frozen=True)
class Caller:
    """Who is calling, resolved from the credential alone.

    `tenant_id` is `None` for the provider and a real tenant id for a tenant console. There is
    deliberately no third state and no "unknown" caller: an unrecognised credential never
    produces a `Caller` at all, it produces a 401.
    """

    kind: str  # "provider" | "tenant"
    tenant_id: Optional[str] = None

    @property
    def is_provider(self) -> bool:
        return self.kind == "provider"


def authenticate_caller(request: Request) -> Caller:
    """Resolve the bearer token to a `Caller`, or refuse.

    Fails **closed**: with no provider token configured every request is refused rather than
    admitted with nothing to check, the same instinct the gateway's distributed mode uses
    (Tier-0 F-23). Tenant tokens are compared one at a time with `compare_digest` rather than
    looked up in the dict directly — the table is small, and a dict lookup on a secret is a
    timing side channel for the same reason a `==` on one is.
    """
    settings = request.app.state.settings
    if not settings.api_token:
        raise HTTPException(status_code=401, detail="catalog service has no api_token configured")

    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    if secrets.compare_digest(token, settings.api_token):
        return Caller(kind="provider")
    for candidate, tenant_id in settings.tenant_tokens.items():
        if secrets.compare_digest(token, candidate):
            return Caller(kind="tenant", tenant_id=tenant_id)
    raise HTTPException(status_code=401, detail="invalid or missing bearer token")


async def _named_tenants(request: Request) -> list[str]:
    """Every tenant this request names, from the path and from the body.

    Reading the body here is safe and deliberate: Starlette caches it on the request, so the
    route's own model parsing still sees it. The alternative — checking the path in a
    dependency and the body in each handler — is two enforcement points for one rule, which is
    how the drift §7a found happens.
    """
    named = []
    path_tenant = request.path_params.get("tenant_id")
    if isinstance(path_tenant, str):
        named.append(path_tenant)

    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001 — a body that is absent, empty or not JSON names no
            # tenant. It is not this dependency's job to reject it: the route's own model
            # validation gives a far better error than anything guessable from here.
            body = None
        if isinstance(body, dict):
            named.extend(str(body[key]) for key in _TENANT_BODY_KEYS if isinstance(body.get(key), str))
    return named


async def enforce_tenant_scope(request: Request, caller: Caller = Depends(authenticate_caller)) -> Caller:
    """The one place the tenant-from-the-credential rule is enforced.

    A provider caller may name any tenant — that is what "read everything" means. A tenant
    caller may name only itself, on every route that names a tenant at all, whether in the path
    or in the body.
    """
    if caller.is_provider:
        return caller

    for named in await _named_tenants(request):
        if named != caller.tenant_id:
            logger.warning(
                "catalog: refusing {method} {path} — caller tenant {caller_tenant!r} named tenant {named!r} "
                "(ADR-0020 §7a: the tenant is read from the credential, never from the request)",
                method=request.method,
                path=request.url.path,
                caller_tenant=caller.tenant_id,
                named=named,
            )
            raise HTTPException(
                status_code=403,
                detail="this credential may only act for its own tenant",
            )
    return caller


def require_provider(request: Request, caller: Caller = Depends(enforce_tenant_scope)) -> Caller:
    """Gate a route on the provider caller class.

    Depends on `enforce_tenant_scope` rather than `authenticate_caller` so that a route can
    never accidentally acquire provider-gating *without* the scope rule; there is no ordering
    for a future route to get wrong.
    """
    if not caller.is_provider:
        logger.warning(
            "catalog: refusing {method} {path} — provider-only route, caller is tenant {caller_tenant!r}",
            method=request.method,
            path=request.url.path,
            caller_tenant=caller.tenant_id,
        )
        raise HTTPException(status_code=403, detail="this route is provider-only")
    return caller
