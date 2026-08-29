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

**And, since §7b: a tenant caller declares which tenant it believes it serves, on every
request.** The two rules above both trust the credential completely — that is their job — so
neither can notice a credential that was *delivered to the wrong console*. The declaration is
the second assertion needed to see that two things disagree: `X-Catalog-Tenant` carries what
the deployment thinks it is, the credential carries what it actually holds, and a difference
between them is a provisioning failure rather than a request-time one. It is **required** of a
tenant caller, because an optional declaration is a check with an opt-out, taken by exactly the
deployment that got it wrong.

A mismatch is **refused, never filtered to empty and never rewritten to the caller's own
tenant** — the disagreement is the signal, and silently reinterpreting it would destroy the
only evidence that something asked for a neighbour's data.

**On "audited".** §7a says refusals are audited; this service has no audit chain of its own
(the console BFF is the audit writer, and giving a second component one was explicitly not the
plan). What exists here is a structured `WARNING` per refusal, carrying both tenants and the
route. That is weaker than the BFF's hash-chained records and is stated rather than implied.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request
from loguru import logger

from . import metrics

#: The header a tenant caller uses to declare which tenant it believes it serves (§7b).
TENANT_HEADER = "X-Catalog-Tenant"


def hash_credential(value: str) -> str:
    """The stored form of an issued tenant credential (ADR-0024 §10).

    Plain SHA-256 rather than a password KDF, matching the gateway's `enrolments.py`: these
    are full-entropy machine-generated secrets, so there is no dictionary for a KDF to slow an
    attacker against, and this runs on every authenticated request.
    """
    return hashlib.sha256(value.encode()).hexdigest()


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


async def authenticate_caller(request: Request) -> Caller:
    """Resolve the bearer token to a `Caller`, or refuse.

    Fails **closed**: with no provider token configured every request is refused rather than
    admitted with nothing to check, the same instinct the gateway's distributed mode uses
    (Tier-0 F-23). Configured tenant tokens are compared one at a time with `compare_digest`
    rather than looked up in the dict directly — the table is small, and a dict lookup on a
    secret is a timing side channel for the same reason a `==` on one is.

    **Two sources of tenant credential, checked in that order** (ADR-0024 §10). Config first,
    because it needs no database and is how a tenant predating enrolment is bootstrapped; then
    the `tenant_credentials` table, which is where a credential minted by approving an
    enrolment lives. Config is checked first deliberately: it is the path that still works when
    the store is down, so an estate that has not adopted enrolment is unaffected by the
    catalog's own database being unavailable.
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

    issued = await _issued_tenant_caller(request, token)
    if issued is not None:
        return issued
    raise HTTPException(status_code=401, detail="invalid or missing bearer token")


async def _issued_tenant_caller(request: Request, token: str) -> Optional[Caller]:
    """Look up an enrolment-issued credential in the `tenant_credentials` table.

    Live on every request, with no caching: revocation is the only control an issued
    credential has, so it has to take effect on the next request rather than at the next
    refresh of something remembered. That is the same argument ADR-0024 §10 makes for the
    gateway's own enrolment credential, and it applies here for the same reason.

    **An unreachable database is a named 503, never a 401.** The distinction matters more than
    it looks: a 401 tells an operator their credential is wrong, so an outage would be
    diagnosed as a misconfiguration — sending someone to re-issue a credential that was fine.
    ADR-0020 §7 already requires this service's unavailability to be a named condition rather
    than something inferred; this is that rule reaching the one path where the wrong answer is
    actively misleading rather than merely unhelpful.
    """
    from .repo import TenantCredentialRepo

    db = getattr(request.app.state, "db", None)
    if db is None or not request.app.state.settings.database_url:
        # NO STORE CONFIGURED. Nothing to look up, and nothing to claim is wrong with the
        # credential — `/readyz` is where "this service has no database" is reported, and it
        # must not be re-reported here as an authentication failure.
        #
        # `settings.database_url` is what distinguishes this from the outage below, and it has
        # to be: `Database.pool` RAISES when the pool is absent, and it is absent in BOTH cases
        # — never configured, and configured but unreachable at startup. Checking the pool
        # alone cannot tell them apart, which is exactly the confusion this function exists to
        # prevent. `/readyz` already makes the same split for the same reason.
        return None
    try:
        tenant_id = await TenantCredentialRepo(db).tenant_for(hash_credential(token))
    except Exception as exc:  # noqa: BLE001 — see the docstring: availability, not validity.
        logger.error(
            "catalog: cannot verify an issued tenant credential — the database is unreachable: {exc}",
            exc=exc,
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "ERR_CATALOG_STORE_UNAVAILABLE",
                "message": (
                    "the catalog cannot verify credentials right now because its database is "
                    "unreachable. This is not a rejection of your credential (ADR-0020 §7)."
                ),
            },
        ) from exc
    if tenant_id is None:
        return None
    return Caller(kind="tenant", tenant_id=tenant_id)


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


def _check_declaration(request: Request, caller: Caller) -> None:
    """Refuse a credential that does not belong to the console presenting it (§7b).

    Runs **before** the scope check below, and the order is not incidental. The scope check
    compares a request's assertions against the credential; if the credential itself is the
    wrong one, a request that names its own tenant passes that check perfectly — the caller
    is consistently wrong. Identity has to be settled before consistency means anything.
    """
    declared = request.headers.get(TENANT_HEADER, "").strip()

    if caller.is_provider:
        # The provider console never declares a tenant, because it speaks for none. A
        # declaration arriving with the provider's credential therefore means that credential
        # is installed in a tenant's console — the exact misdelivery §7b names, and the case
        # nothing else in this service can see.
        if declared:
            _refuse_misdelivery(request, declared=declared, caller=caller)
        return

    if not declared:
        metrics.tenant_declaration_missing_total.labels(credential_tenant=caller.tenant_id or "").inc()
        logger.warning(
            "catalog: refusing {method} {path} — tenant caller {caller_tenant!r} declared no tenant "
            "(ADR-0020 §7b: a tenant caller declares the tenant it believes it serves)",
            method=request.method,
            path=request.url.path,
            caller_tenant=caller.tenant_id,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "ERR_TENANT_NOT_DECLARED",
                "message": (
                    f"a tenant caller must declare its tenant in {TENANT_HEADER} (ADR-0020 §7b). "
                    "This request was refused rather than served, because a credential nobody "
                    "checks against a deployment is a credential nobody would notice was misdelivered."
                ),
            },
        )

    if declared != caller.tenant_id:
        _refuse_misdelivery(request, declared=declared, caller=caller)


def _refuse_misdelivery(request: Request, *, declared: str, caller: Caller) -> None:
    """One refusal path for both misdelivery shapes, so they alert as one condition."""
    metrics.credential_misdelivery_total.labels(declared_tenant=declared, credential_kind=caller.kind).inc()
    logger.error(
        "catalog: CREDENTIAL MISDELIVERY on {method} {path} — a console declaring itself tenant "
        "{declared!r} presented a {kind} credential"
        "{owner}. The credential is valid and is deployed in the wrong console; every catalog "
        "feature there is refused until it is corrected (ADR-0020 §7b).",
        method=request.method,
        path=request.url.path,
        declared=declared,
        kind=caller.kind,
        owner=f" belonging to {caller.tenant_id!r}" if caller.tenant_id else "",
    )
    raise HTTPException(
        status_code=403,
        detail={
            "error_code": "ERR_CREDENTIAL_MISDELIVERY",
            "message": (
                f"this credential does not belong to tenant '{declared}' (ADR-0020 §7b). It is a "
                "valid credential in the wrong deployment — correct the provisioning rather than "
                "the request."
            ),
        },
    )


async def enforce_tenant_scope(request: Request, caller: Caller = Depends(authenticate_caller)) -> Caller:
    """The one place the tenant-from-the-credential rules are enforced.

    Two questions, in order. **Is this credential in the right console?** (§7b — the
    declaration.) Then: **is this request asking about the right tenant?** (§7a — the scope.)
    A provider caller may name any tenant, which is what "read everything" means; a tenant
    caller may name only itself, on every route that names a tenant at all, in the path or in
    the body.
    """
    _check_declaration(request, caller)

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
