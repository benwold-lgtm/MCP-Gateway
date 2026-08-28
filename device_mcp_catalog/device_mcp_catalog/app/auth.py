# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""A single shared bearer token gates every curation route.

Phase 1 has exactly one caller (the console BFF's `CatalogClient`) — see the plan's own
reasoning for not building a scope model with no second caller yet to justify it. Fails
**closed**: an unconfigured token refuses every request rather than admitting one with no
token to check, the same instinct the gateway's own distributed mode uses (Tier-0 F-23:
refuses rather than silently running unauthenticated).

⚠️ **THE "EXACTLY ONE CALLER" PRECONDITION IS ALREADY BROKEN IN CODE, THOUGH NOT YET IN ANY
DEPLOYMENT.** The tenant console's own catalog routes (`routers/api.py` in the UI repo:
`_assigned_types`, `/catalog/{type_id}/claim`, `/catalog/upgrades`) read this service
directly, through the same client and therefore this same token. Wiring a tenant stack to a
catalog would hand every tenant's BFF the provider's credential — and nothing here scopes a
caller to a tenant, so a holder can read any tenant's assignments (the tenant comes from the
URL path), record claims for any tenant (from the request body), curate types and assign them.

**Do not configure a tenant-side `CATALOG_SERVICE_URL` until this is fixed.**
[ADR-0020 §7a](../../../docs/adr/0020-the-device-catalog.md) records the decision: two caller
classes, with the tenant derived from the credential and never from the request. Until then
this module is correct only for the single-caller topology it was written for, which is why
this warning is here rather than in the amendment alone.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request


def require_api_token(request: Request) -> None:
    settings = request.app.state.settings
    if not settings.api_token:
        raise HTTPException(status_code=401, detail="catalog service has no api_token configured")

    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or not secrets.compare_digest(token, settings.api_token):
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")
