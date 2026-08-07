# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Streamable HTTP inbound transport (Phase 6, Workstream A).

The gateway's only inbound transport has been **HTTP+SSE** — `GET /sse` returning an
`endpoint` event, then `POST /messages?session_id=`. That transport is formally Deprecated
with a removal clock, and `transport != "sse"` is a hard reject elsewhere, so there is no
fallback. Streamable HTTP is owed regardless of whether we adopt revision `2026-07-28`.

**Semantics here are unchanged** — this is revision `2025-06-18` over a different transport.
Sessions still exist. The modern stateless era is Workstream B and lands on top of this.

Deliberately a **separate path** (`/mcp`) rather than content negotiation on `/messages`:
HTTP+SSE is scheduled for removal one minor release after this ships, and a separate path
makes that a deletion rather than an unpicking.

⚠️ **Embedded mode only, and only until Workstream A2.** Distributed mode needs a POST
landing on any replica to await a result produced by a worker and published to Redis —
see ``api/exchange.py``. Until that exists this endpoint answers 501 rather than pretending,
and the refusal says *not yet* rather than *not here*, because unlike the dead-letter queue's
mode gate this one is a construction stage rather than an architectural property.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.api.exchange import (
    EmbeddedResultExchange,
    ExchangeTimeout,
    ExchangeUnavailable,
    ResultExchange,
)
from device_mcp_gateway.audit import audit_log
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.rbac import SCOPE_TOOLS_CALL, require_scope
from device_mcp_gateway.registry.server import Registry

router = APIRouter()

#: Header carrying the session identifier, per the Streamable HTTP transport.
SESSION_HEADER = "Mcp-Session-Id"
#: Header a client uses to state the revision it is speaking on non-initialize requests.
PROTOCOL_HEADER = "MCP-Protocol-Version"


def _require_embedded(request: Request) -> None:
    """Refuse in distributed mode — Workstream A2 has not landed yet.

    501 rather than the dead-letter queue's 400: the caller has not made a mistake, and this
    is not a permanent property of the deployment. 501 is "the server does not support the
    functionality required to fulfil the request", which is the true statement, and it turns
    into a normal response in A2 without having promised a contract in the meantime.
    """
    if request.app.state.mode != "distributed":
        return
    raise HTTPException(
        status_code=501,
        detail=(
            "Streamable HTTP inbound is not yet available in distributed mode — it is "
            "implemented for embedded mode only in this release. Use the SSE transport "
            "(GET /v1/devices/{hostname}/sse) until distributed support ships."
        ),
    )


def _exchange_for(request: Request) -> ResultExchange:
    """The exchange implementation for this deployment.

    Only the embedded one exists today; A2 adds the distributed sibling and this is the one
    place that has to learn about it.
    """
    return EmbeddedResultExchange(request.app.state.registry)


def _check_accept(request: Request) -> None:
    """The transport requires the client to accept both response shapes.

    Enforced rather than assumed: a client that accepts only JSON would break the moment a
    response is streamed, and finding that out at the first long tool call is worse than
    being told at the handshake.
    """
    accept = request.headers.get("accept", "")
    if not accept or "*/*" in accept:
        return
    if "application/json" not in accept:
        raise HTTPException(
            status_code=406,
            detail="Accept must include application/json (and text/event-stream for streamed responses)",
        )


async def _read_payload(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be JSON-RPC 2.0")
    if not isinstance(payload, dict):
        # Batching was removed in 2025-06-18; a list here is a client on an older revision.
        raise HTTPException(
            status_code=400,
            detail="Expected a single JSON-RPC object; batched requests are not supported",
        )
    return payload


def _session_state(request: Request) -> dict[str, str]:
    """Embedded session→owner map, shared with the SSE path so F-37 holds across transports."""
    return request.app.state.session_owners


@router.post(
    "/devices/{hostname}/mcp",
    dependencies=[
        Depends(require_scope(SCOPE_TOOLS_CALL)),
        # Same budgets as the SSE message route: this is the same operation over a
        # different transport, so a client must not get a second allowance by switching.
        Depends(rate_limit("600/minute", "messages")),
        Depends(rate_limit_principal("1200/minute", "messages")),
    ],
)
async def device_streamable_post(hostname: str, request: Request, response: Response):
    """Accept one JSON-RPC message and answer it on this response."""
    _require_embedded(request)
    _check_accept(request)

    reg: Registry = request.app.state.registry
    device = await reg.get_device(hostname)
    if not device or not device.pod_active:
        raise HTTPException(status_code=404, detail="Device pod not found or not active")

    payload = await _read_payload(request)
    method = payload.get("method", "")
    msg_id = payload.get("id")
    _principal = getattr(request.state, "principal", None)
    _subject = _principal.subject if _principal else "unknown"
    _rid = getattr(request.state, "request_id", "-")

    sessions = _session_state(request)
    session_id = request.headers.get(SESSION_HEADER)

    if method == "initialize":
        # The server mints the id, as on the SSE path — a client-supplied one would let a
        # caller graft themselves onto another principal's session.
        session_id = str(uuid.uuid4())
        sessions[session_id] = _subject  # F-37: bind the session to its opener
        response.headers[SESSION_HEADER] = session_id
    elif session_id is not None:
        owner = sessions.get(session_id)
        if owner is None:
            # Spec: an unknown/expired session id must be rejected so the client re-initializes.
            raise HTTPException(status_code=404, detail="Unknown or expired session")
        if owner != _subject:
            raise HTTPException(status_code=403, detail="Session is bound to a different principal")

    _t = time.perf_counter()
    try:
        result = await _exchange_for(request).exchange(
            hostname,
            payload,
            session_id=session_id or "",
            subject=_subject,
            rid=_rid,
        )
    except ExchangeUnavailable as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except ExchangeTimeout as exc:
        # 504, not 500: the call may still be running upstream, so this is not a failed tool
        # call and a client is entitled to treat it as retryable at its own discretion.
        raise HTTPException(status_code=504, detail=str(exc) or "Timed out awaiting device response") from exc
    _dur = (time.perf_counter() - _t) * 1000

    _status = "error" if isinstance(result, dict) and "error" in result else "ok"
    metrics.tool_calls_total.labels(hostname=hostname, method=method or "?", status=_status).inc()
    metrics.tool_call_duration_seconds.labels(hostname=hostname).observe(_dur / 1000.0)
    audit_log(
        "tool dispatch",
        hostname=hostname,
        subject=_subject,
        method=method or "?",
        status=_status,
        duration_ms=round(_dur, 1),
        rid=_rid,
        transport="streamable-http",
    )

    if result is None:
        # A notification (no id) has no response. 202 with an empty body is what the
        # transport specifies; returning `null` would be a malformed JSON-RPC response.
        return Response(status_code=202, headers=dict(response.headers))
    if msg_id is None:
        logger.warning(f"Discarding a response to an id-less message on {hostname} (method={method!r})")
        return Response(status_code=202, headers=dict(response.headers))
    return Response(
        content=json.dumps(result),
        media_type="application/json",
        headers=dict(response.headers),
    )


@router.get("/devices/{hostname}/mcp", dependencies=[Depends(require_scope(SCOPE_TOOLS_CALL))])
async def device_streamable_get(hostname: str, request: Request):
    """No server-initiated stream is offered at this endpoint.

    The transport says a server that does not offer one here MUST answer 405, and we
    genuinely do not: the gateway advertises no server-initiated capability
    (`listChanged: false`, no sampling, no roots), so there is nothing to push. Answering
    405 is the honest reading, and it is what tells a conforming client to stop asking.
    """
    _require_embedded(request)
    raise HTTPException(status_code=405, detail="This endpoint offers no server-initiated stream")


@router.delete("/devices/{hostname}/mcp", dependencies=[Depends(require_scope(SCOPE_TOOLS_CALL))])
async def device_streamable_delete(hostname: str, request: Request):
    """Explicit session termination by the client."""
    _require_embedded(request)
    session_id = request.headers.get(SESSION_HEADER)
    if not session_id:
        raise HTTPException(status_code=400, detail=f"{SESSION_HEADER} is required to terminate a session")
    _principal = getattr(request.state, "principal", None)
    _subject = _principal.subject if _principal else "unknown"
    sessions = _session_state(request)
    owner = sessions.get(session_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Unknown or expired session")
    if owner != _subject:
        raise HTTPException(status_code=403, detail="Session is bound to a different principal")
    sessions.pop(session_id, None)
    return Response(status_code=204)
