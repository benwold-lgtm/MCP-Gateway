# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""A single shared bearer token gates every curation route.

Phase 1 has exactly one caller (the console BFF's `CatalogClient`) — see the plan's own
reasoning for not building a scope model with no second caller yet to justify it. Fails
**closed**: an unconfigured token refuses every request rather than admitting one with no
token to check, the same instinct the gateway's own distributed mode uses (Tier-0 F-23:
refuses rather than silently running unauthenticated).
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
