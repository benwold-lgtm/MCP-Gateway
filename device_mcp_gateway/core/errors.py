# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Central error catalog (Tier-1 F-51).

A distributed failure used to reach the caller as an opaque 30 s timeout or an
error-shaped "successful" result, with the correlating request id (`rid`) only in
server logs. This module is the single, documented taxonomy of every error the
gateway surfaces, in two layers:

  - **Application layer** — `error.type` slugs inside a tool-result envelope (F-39),
    for failures where the call *reached* the device path (`ENVELOPE_CATALOG`).
  - **Protocol layer** — JSON-RPC error codes returned on the MCP channel
    (`RPC_CATALOG`), for failures before/around dispatch (bad params, no worker, …).

`rpc_error()` builds a consistent JSON-RPC error object whose ``data`` carries the
stable ``reason`` slug and the ``rid`` (and the internal ``request_id`` when known),
so a client can tell "no worker" from "device down" from "bad arguments" and
correlate the failure with the access log without guessing. The catalogs are also
the source of truth for ``docs/error-catalog.md`` (kept in sync by a test).
"""

from __future__ import annotations

from typing import Any

# --- Application layer: tool-result envelope error.type slugs (F-39) ----------
ERR_HTTP = "http_error"
ERR_TOO_LARGE = "response_too_large"
ERR_CIRCUIT_OPEN = "circuit_open"
ERR_TIMEOUT = "timeout"
ERR_CONNECTION = "connection_error"
ERR_INTERNAL = "internal"

# slug -> (meaning, likely cause)
ENVELOPE_CATALOG: dict[str, tuple[str, str]] = {
    ERR_HTTP: (
        "Upstream device returned an HTTP error (status >= 400).",
        "A 4xx is usually a bad request/auth; a 5xx is a device-side fault.",
    ),
    ERR_TOO_LARGE: (
        "Upstream response exceeded the size cap and was not buffered.",
        "The device returned a body larger than the gateway's response limit.",
    ),
    ERR_CIRCUIT_OPEN: (
        "The device's circuit breaker is open; the call was short-circuited.",
        "Repeated 5xx/connection failures tripped the breaker; it resets after a cooldown.",
    ),
    ERR_TIMEOUT: (
        "The request to the device timed out.",
        "The device was slow or unresponsive within the request timeout.",
    ),
    ERR_CONNECTION: (
        "Could not connect to the device.",
        "DNS failure, connection refused/reset, or TLS error reaching the base_url.",
    ),
    ERR_INTERNAL: (
        "Unexpected gateway-side error while handling the call.",
        "A gateway/pod bug or an unhandled device response — check server logs via rid.",
    ),
}

# --- Protocol layer: JSON-RPC error codes -------------------------------------
# Standard JSON-RPC 2.0 codes:
RPC_METHOD_NOT_FOUND = -32601
RPC_INVALID_PARAMS = -32602
# Server-defined range (-32000..-32099):
RPC_INTERNAL_ERROR = -32000
RPC_NO_WORKER = -32001
RPC_DUPLICATE = -32002

# code -> (reason slug, default message/meaning, likely cause)
RPC_CATALOG: dict[int, tuple[str, str, str]] = {
    RPC_METHOD_NOT_FOUND: (
        "method_not_found",
        "Unknown MCP method or tool name.",
        "The tool isn't in the device manifest, or an unsupported MCP method was called.",
    ),
    RPC_INVALID_PARAMS: (
        "invalid_params",
        "Request arguments failed validation.",
        "Missing/extra/wrong-typed tool arguments, or a malformed resource URI/path.",
    ),
    RPC_INTERNAL_ERROR: (
        "internal_error",
        "The tool handler raised an unexpected error.",
        "A gateway/pod bug or an unhandled device response — correlate with rid in the logs.",
    ),
    RPC_NO_WORKER: (
        "no_worker",
        "The call was accepted but no worker served it in time.",
        "No worker owns the device, the owning worker died, or it is saturated/slow (distributed mode).",
    ),
    RPC_DUPLICATE: (
        "duplicate_suppressed",
        "A duplicate delivery of a non-idempotent call was suppressed (F-08).",
        "The call was redelivered (a worker died/shed the device mid-flight) after a prior attempt "
        "had begun; re-running a non-idempotent operation could double-apply, so it was not retried. "
        "Retry explicitly if the operation is safe to repeat.",
    ),
}


def rpc_error(
    code: int,
    msg_id: Any,
    *,
    rid: str | None = None,
    request_id: str | None = None,
    message: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response with a structured, catalogued ``data`` block.

    ``data`` carries the stable ``reason`` slug plus the correlating ``rid`` (the
    gateway request id, also in the access log) and ``request_id`` (the internal
    call-correlation id) when known, so the caller can diagnose and cross-reference.
    """
    slug, default_msg, _cause = RPC_CATALOG.get(code, ("error", "Error.", ""))
    data: dict[str, Any] = {"reason": slug}
    if rid is not None and rid != "-":
        data["rid"] = rid
    if request_id is not None:
        data["request_id"] = request_id
    if detail is not None:
        data["detail"] = detail
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": code, "message": message or default_msg, "data": data},
    }


__all__ = [
    "ERR_HTTP",
    "ERR_TOO_LARGE",
    "ERR_CIRCUIT_OPEN",
    "ERR_TIMEOUT",
    "ERR_CONNECTION",
    "ERR_INTERNAL",
    "ENVELOPE_CATALOG",
    "RPC_METHOD_NOT_FOUND",
    "RPC_INVALID_PARAMS",
    "RPC_INTERNAL_ERROR",
    "RPC_NO_WORKER",
    "RPC_DUPLICATE",
    "RPC_CATALOG",
    "rpc_error",
]
