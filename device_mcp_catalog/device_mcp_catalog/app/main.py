# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The catalog service (ADR-0020): provider-plane device-type curation and assignment.

Slice 0 (this file, today): process + database lifecycle only — `/healthz` (liveness: the
process is up) and `/readyz` (readiness: the database is reachable). No curation routes yet;
those land in slice 1 on top of this scaffolding.

`/readyz` reporting the database down is a **named condition**, not a crash and not an empty
result indistinguishable from "nothing curated yet" — the same discipline ADR-0018 §7 already
holds the gateway's credential resolver to, which ADR-0020 §7 explicitly extends to this
service: "its unavailability is a named condition... a provider console showing no device
types because a database is down must not look like a provider who has curated none."
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from loguru import logger

from .config import load_settings
from .db import Database


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = load_settings()
    app.state.settings = settings
    db = Database(settings.database_url)
    if settings.database_url:
        try:
            await db.connect()
        except Exception as exc:  # noqa: BLE001 — a bad/unreachable DB at startup must
            # surface on /readyz, never crash the process: a misconfigured deployment
            # (or a database that hasn't finished starting yet in a rolling deploy) is
            # exactly the "named condition, not a crash" case ADR-0020 §7 requires.
            logger.warning(f"catalog database unavailable at startup, continuing degraded: {exc}")
    app.state.db = db
    try:
        yield
    finally:
        await db.close()


def create_app() -> FastAPI:
    app = FastAPI(title="device-mcp-catalog", lifespan=_lifespan)

    @app.get("/healthz")
    async def healthz() -> dict:
        # Liveness only: the process can answer HTTP at all. Never checks the database —
        # that's what readiness is for, and conflating the two would make a database blip
        # restart a perfectly healthy process for no reason.
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        db: Database = app.state.db
        if not app.state.settings.database_url:
            return JSONResponse(status_code=503, content={"status": "unavailable", "reason": "no database configured"})
        if not await db.ping():
            return JSONResponse(status_code=503, content={"status": "unavailable", "reason": "database unreachable"})
        return JSONResponse(status_code=200, content={"status": "ok"})

    return app


def run() -> None:
    """Entry point for the `device-mcp-catalog` console script."""
    import uvicorn

    settings = load_settings()
    uvicorn.run(create_app(), host=settings.host, port=settings.port)
