# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Shared distributed-dispatch helpers for the SSE and fleet routes.

The gateway identity tag and the F6 lost-call watcher are needed by both the
per-device (``api/sse.py``) and fleet (``api/fleet.py``) message routes; they live
here so neither route module depends on the other or on ``main``.
"""

from __future__ import annotations

import asyncio
import os
import uuid

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.core.errors import RPC_NO_WORKER, rpc_error

# Gateway instance ID — used to tag SSE sessions in distributed mode.
_GATEWAY_ID = os.getenv("GATEWAY_ID", str(uuid.uuid4()))


async def _watch_tool_call_timeout(
    redis, session_router, session_id, request_id, msg_id, timeout, hostname="?", rid=None
):
    """Emit a JSON-RPC timeout error on the SSE stream if no worker responds.

    Cross-replica safe: the worker sets result:{request_id} in Redis when it
    handles the call, so this watcher (which may run on a different gateway
    replica than the one holding the SSE stream) checks that shared marker
    rather than observing the pub/sub channel directly (F6). The emitted error
    carries the catalogued `no_worker` reason + the rid so the caller can
    diagnose and correlate with the access log (F-51).
    """
    try:
        await asyncio.sleep(timeout)
        if await redis.get(f"result:{request_id}"):
            return  # worker handled it
        metrics.tool_call_timeouts_total.labels(hostname=hostname).inc()
        await session_router.publish_result(
            session_id,
            rpc_error(
                RPC_NO_WORKER,
                msg_id,
                rid=rid,
                request_id=request_id,
                message=f"Tool call timed out after {timeout}s — no worker responded",
            ),
        )
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.warning(f"tool-call timeout watcher failed for request {request_id}")


def spawn_timeout_watcher(request, session_router, session_id, request_id, msg_id, hostname, rid) -> None:
    """Schedule the F6 watcher for one dispatched call, holding a strong ref on
    ``app.state.bg_tasks`` so it isn't GC'd mid-sleep."""
    cfg = request.app.state.config
    timeout = cfg.get("registry", {}).get("tool_call_timeout", 30)
    watcher = asyncio.create_task(
        _watch_tool_call_timeout(
            request.app.state.redis,
            session_router,
            session_id,
            request_id,
            msg_id,
            timeout,
            hostname,
            rid,
        )
    )
    request.app.state.bg_tasks.add(watcher)
    watcher.add_done_callback(request.app.state.bg_tasks.discard)
