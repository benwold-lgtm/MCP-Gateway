# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Request/response exchange — deliver a JSON-RPC message and return its response *here*.

The existing SSE transport is fire-and-forget at the HTTP layer: a `POST /messages` is
acknowledged, and the JSON-RPC response arrives later on a stream the client already holds
open. Streamable HTTP inverts that — the response belongs to the POST that carried the
request — and that inversion, not the framing, is the actual work.

In embedded mode it is trivial: the pod is in this process, so awaiting it is a call.

In distributed mode it is the hard part of Phase 6, and it is why this seam exists at all.
The POST can land on any gateway replica, while the device is owned by one worker and the
result is published to Redis. The replica handling the POST therefore has to *wait* on a
result it does not produce, correlating by JSON-RPC id — where today it merely publishes the
call and lets whichever replica holds the SSE stream do the delivering.

Defining the boundary now means the distributed implementation is a new subclass rather than
a rewrite of the endpoint that calls it. The endpoints depend on this interface only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

DEFAULT_EXCHANGE_TIMEOUT = 30.0


class ExchangeTimeout(Exception):
    """No response arrived within the deadline.

    Distinct from an upstream error: the call may still be running, so the caller must not
    report it as a failed tool call. Streamable HTTP maps this to 504.
    """


class ExchangeUnavailable(Exception):
    """The device cannot serve this request at all (no pod, wrong mode, shedding).

    Carries an HTTP status so a transport can answer correctly without re-deriving why.
    """

    def __init__(self, detail: str, status_code: int = 503) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class ResultExchange(ABC):
    """Deliver one JSON-RPC message to a device and return its response.

    Implementations must be safe to call concurrently for the same device: several clients
    may hold Streamable HTTP requests against one hostname at once.
    """

    @abstractmethod
    async def exchange(
        self,
        hostname: str,
        payload: dict[str, Any],
        *,
        session_id: str,
        subject: str,
        rid: str,
        timeout: float = DEFAULT_EXCHANGE_TIMEOUT,
    ) -> dict[str, Any] | None:
        """Return the JSON-RPC response, or None when ``payload`` is a notification.

        Raises ``ExchangeTimeout`` if no response arrives in ``timeout`` seconds, and
        ``ExchangeUnavailable`` when the device cannot serve the request.
        """


class EmbeddedResultExchange(ResultExchange):
    """In-process: the pod is right here, so awaiting it is a direct call.

    No timeout is enforced here on purpose. The pod already owns the bounds that matter —
    the per-device token bucket, the circuit breaker and the upstream HTTP timeout — and
    layering a second deadline on top would report a timeout for a call the pod is about to
    answer, which is exactly the confusion ``ExchangeTimeout`` exists to avoid.
    """

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    async def exchange(
        self,
        hostname: str,
        payload: dict[str, Any],
        *,
        session_id: str,
        subject: str,
        rid: str,
        timeout: float = DEFAULT_EXCHANGE_TIMEOUT,
    ) -> dict[str, Any] | None:
        profile = self._registry.get_profile(hostname)
        if not profile or not profile.pod:
            raise ExchangeUnavailable(f"Device '{hostname}' has no active pod", status_code=404)
        return await profile.pod.call_tool(payload)
