# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Per-device request/response adapter seam (Tier-1 F-49).

Two integration concerns vary by upstream API and were previously hard-coded in the
pod's tool closure:

  - **Request encoding (F-40):** the body was always sent as ``json=``, so form,
    multipart, and binary uploads were broken. ``encode_body`` maps a tool's
    ``RequestBodySpec`` to the right httpx request kwargs.
  - **Result normalization (F-39):** the pod returned three inconsistent shapes and an
    upstream ``>=400`` looked like a *successful* MCP result. ``build_result`` /
    ``error_envelope`` emit one uniform envelope where ``ok`` reflects real success.

``DeviceAdapter`` is the seam: the default implementation handles standard OpenAPI
content types and a uniform envelope; a future per-device subclass can override either
half (e.g. a device that needs request signing or a bespoke error mapping) and be
selected at pod construction.

Result envelope (always one of):
    {"ok": True,  "status": <int>, "body": <parsed|None>}
    {"ok": False, "status": <int|None>, "error": {"type": <str>, "message": <str>},
                  "body": <parsed error body, optional>}

``error.type`` is a small stable catalog so callers/clients can branch without parsing
prose: ``http_error``, ``response_too_large``, ``circuit_open``, ``timeout``,
``connection_error``, ``internal``.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from device_mcp_gateway.core.errors import (
    ERR_CIRCUIT_OPEN,
    ERR_CONNECTION,
    ERR_HTTP,
    ERR_INTERNAL,
    ERR_TIMEOUT,
    ERR_TOO_LARGE,
)
from device_mcp_gateway.core.translator import (
    FORM_CONTENT,
    JSON_CONTENT,
    MULTIPART_CONTENT,
    McpTool,
)


class DeviceAdapter:
    """Default request-encoder + response-normalizer for a device pod (F-49)."""

    def __init__(self, max_response_bytes: int) -> None:
        self._max_response_bytes = max_response_bytes

    # ---- Request side (F-40) ----

    def encode_body(self, tool: McpTool, body_params: dict[str, Any]) -> dict[str, Any]:
        """Return the httpx request kwargs that carry ``body_params`` for this tool.

        Only methods with a body (POST/PUT/PATCH) and a declared ``request_body`` are
        encoded per its content type; everything else falls back to JSON so behaviour
        is unchanged for the common case.
        """
        spec = tool.request_body
        if spec is None or tool.method not in ("POST", "PUT", "PATCH"):
            # No body schema (or a GET/DELETE that somehow has body params): preserve the
            # historical default of a JSON body when there is anything to send.
            return {"json": body_params} if body_params else {}

        if spec.raw:
            value = body_params.get(spec.raw_field or "body")
            if value is None:
                return {}
            return {"content": self._as_bytes(value), "headers": {"content-type": spec.content_type}}

        # Map any collision-renamed body fields back to their upstream wire name (F-04).
        wire = tool.param_wire_names

        if spec.content_type == FORM_CONTENT:
            # application/x-www-form-urlencoded — httpx sets the header from data=.
            return {"data": {wire.get(k, k): v for k, v in body_params.items()}}

        if spec.content_type == MULTIPART_CONTENT:
            files: dict[str, Any] = {}
            data: dict[str, Any] = {}
            for k, v in body_params.items():
                name = wire.get(k, k)
                if k in spec.binary_fields:
                    files[name] = self._as_bytes(v)
                else:
                    data[name] = v
            kwargs: dict[str, Any] = {}
            if files:
                kwargs["files"] = files
            if data:
                kwargs["data"] = data
            # httpx requires files= to set the multipart boundary; if a multipart op had
            # no binary field declared, fall back to data= (still multipart on the wire
            # only when files present — otherwise urlencoded, which servers accept).
            return kwargs

        # application/json and any unknown/JSON-ish type.
        return {"json": {wire.get(k, k): v for k, v in body_params.items()}}

    @staticmethod
    def _as_bytes(value: Any) -> bytes:
        """Coerce a tool-supplied scalar into request bytes for a raw/file part."""
        if isinstance(value, bytes):
            return value
        return str(value).encode("utf-8")

    # ---- Response side (F-39) ----

    def build_result(self, resp: httpx.Response) -> dict[str, Any]:
        """Normalize a (non-raising) upstream response into the result envelope.

        2xx/3xx → success; 4xx → ``http_error`` (no longer a fake success). 5xx arrives
        here only if the caller did not raise_for_status; it is treated as an error too.
        """
        if len(resp.content) > self._max_response_bytes:
            return self.error_envelope(
                ERR_TOO_LARGE,
                f"Device response too large ({len(resp.content)} bytes > {self._max_response_bytes} limit)",
                status=502,
            )
        body = self._parse_body(resp)
        if resp.status_code >= 400:
            return self.normalize_http_error(resp)
        env: dict[str, Any] = {"ok": True, "status": resp.status_code, "body": body}
        # Surface header-based pagination (RFC 5988 Link / cursor headers) so the LLM
        # can continue past page 1 — otherwise only the body is returned and the
        # cursor is invisible (F-48).
        pagination = self._pagination(resp)
        if pagination:
            env["pagination"] = pagination
        # Surface an async long-running operation (202 + poll location) as a job
        # handle so the model can poll for completion instead of the call appearing
        # done — the gateway is synchronous and can't wait it out (F-45).
        operation = self._async_operation(resp)
        if operation:
            env["operation"] = operation
        return env

    def _async_operation(self, resp: httpx.Response) -> dict[str, Any] | None:
        """Detect an accepted-but-incomplete async operation, or None.

        Triggers on ``202 Accepted`` or an ``Operation-Location`` header (the Azure
        async pattern). ``poll_url`` is where to check status; ``retry_after`` is
        the server's polling hint. ``Location`` is only treated as a poll URL on a
        202 — on a 201 it's the created resource, not a job.
        """
        op_location = resp.headers.get("operation-location")
        if resp.status_code != 202 and op_location is None:
            return None
        operation: dict[str, Any] = {"status": "pending"}
        poll_url = op_location or (resp.headers.get("location") if resp.status_code == 202 else None)
        if poll_url:
            operation["poll_url"] = poll_url
        retry_after = resp.headers.get("retry-after")
        if retry_after is not None:
            operation["retry_after"] = retry_after
        return operation

    # Well-known "next cursor/page" headers (lowercased), checked in order. Body
    # cursors are too vendor-specific to parse generically — they already ride in
    # ``body`` for the LLM to read.
    _CURSOR_HEADERS = ("x-next-cursor", "x-next-page", "next-cursor", "x-cursor", "x-page-token")
    _TOTAL_HEADERS = ("x-total-count", "x-total", "x-total-pages")

    def _pagination(self, resp: httpx.Response) -> dict[str, Any] | None:
        """Extract pagination continuation signals from response headers, or None.

        Uses httpx's parsed RFC 5988 ``Link`` rels plus a small set of common
        cursor/total headers. ``has_more`` is true when a next page is reachable.
        """
        links = {rel: meta["url"] for rel, meta in resp.links.items() if meta.get("url")}
        next_cursor = next((resp.headers[h] for h in self._CURSOR_HEADERS if h in resp.headers), None)
        total = next((resp.headers[h] for h in self._TOTAL_HEADERS if h in resp.headers), None)
        if not links and next_cursor is None and total is None:
            return None
        pagination: dict[str, Any] = {}
        if links.get("next"):
            pagination["next_url"] = links["next"]
        if links:
            pagination["links"] = links
        if next_cursor is not None:
            pagination["next_cursor"] = next_cursor
        if total is not None:
            pagination["total"] = total
        pagination["has_more"] = bool(links.get("next") or next_cursor)
        return pagination

    def normalize_http_error(self, resp: httpx.Response) -> dict[str, Any]:
        """Envelope for an upstream HTTP error response (4xx/5xx) — includes the body."""
        env: dict[str, Any] = {
            "ok": False,
            "status": resp.status_code,
            "error": {
                "type": ERR_HTTP,
                "message": f"Upstream returned HTTP {resp.status_code} {resp.reason_phrase}".strip(),
            },
        }
        if len(resp.content) <= self._max_response_bytes:
            env["body"] = self._parse_body(resp)
        return env

    @staticmethod
    def error_envelope(err_type: str, message: str, *, status: int | None = None) -> dict[str, Any]:
        """Build a uniform error envelope for a locally-detected failure."""
        return {"ok": False, "status": status, "error": {"type": err_type, "message": message}}

    def _parse_body(self, resp: httpx.Response) -> Any:
        """Best-effort decode: JSON object, text, else base64 of the raw bytes."""
        if resp.status_code == 204 or not resp.content:
            return None
        ct = resp.headers.get("content-type", "")
        if "json" in ct:
            try:
                return resp.json()
            except Exception:
                pass
        if ct.startswith("text/"):
            return resp.text
        return base64.b64encode(resp.content).decode()


__all__ = [
    "DeviceAdapter",
    "ERR_HTTP",
    "ERR_TOO_LARGE",
    "ERR_CIRCUIT_OPEN",
    "ERR_TIMEOUT",
    "ERR_CONNECTION",
    "ERR_INTERNAL",
    "JSON_CONTENT",
]
