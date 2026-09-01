# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The correlation id that leaves the gateway (ADR-0026).

ADR-0026 accepts that a device sees **one service identity per device**, not the human
behind the call: every tenant user reaches the same appliance as the same account. The
compensating control — the thing that makes that acceptable rather than merely tolerated
— is that the gateway's audit record and the *device's own* log can be joined afterwards.
Joining them needs one value present on both sides, so this module makes the request id
**egress-visible**: every outbound hop the gateway makes on a caller's behalf carries
``X-Request-Id`` with the same value the access log, the audit record and the response
header already show.

Two properties this file exists to hold:

  * **One seam.** The id is stamped by a request event hook installed on the guarded
    egress client (``security.url_policy.build_guarded_client``), not by each call site.
    A new outbound path therefore gets correlation by construction, and — because the
    hook runs after headers are assembled — an OpenAPI ``in: header`` tool argument
    cannot overwrite it (see ``pods.device_pod._RESERVED_HEADERS`` for the deliberately
    overlapping narrow check).
  * **Never invented at the edge.** If no request id is in context the header is
    *omitted*, never generated here. An id minted at the moment of egress would look
    like a correlation id and join to nothing — worse than its absence, which is at
    least legible as a gap. Both entry points (the gateway's HTTP middleware and the
    worker's stream dispatch) always set a real one, and tests pin that.

What the gateway cannot promise is the *other* half: whether a given device records
inbound headers at all is a property of that device. ADR-0026 makes verifying it a
device-onboarding step rather than an assumption.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

import httpx

#: Emitted on every outbound hop, and returned on every inbound response by the
#: gateway's own middleware, so both directions name the id the same way.
CORRELATION_HEADER = "X-Request-Id"

# Placeholders that mean "no id" on the paths that default rather than omit — the
# worker reads `rid` off a stream entry with a "-" default, and treating that as a
# real id would stamp a literal dash on every device call.
_ABSENT = frozenset({"", "-", "none", "None"})

_current_request_id: ContextVar[str] = ContextVar("mcp_request_id", default="")


def current_request_id() -> str:
    """The request id in scope, or ``""`` when there is none."""
    rid = _current_request_id.get()
    return "" if rid in _ABSENT else rid


@contextmanager
def use_request_id(rid: str | None) -> Iterator[str]:
    """Bind ``rid`` for the duration of the block, restoring the previous value after.

    A context manager rather than a bare setter because the worker dispatches many calls
    in one long-lived task: a set without a reset would leak the previous call's id onto
    an unrelated later one, which is the specific way a correlation id stops being
    evidence and starts being a lie.
    """
    token = _current_request_id.set(rid or "")
    try:
        yield current_request_id()
    finally:
        _current_request_id.reset(token)


async def stamp_correlation(request: httpx.Request) -> None:
    """httpx request hook: put the in-scope request id on the outbound hop.

    Assignment, not ``setdefault`` — this must win over anything already on the request,
    because one of the things that may have set it is an attacker-controlled tool
    argument.
    """
    rid = current_request_id()
    if rid:
        request.headers[CORRELATION_HEADER] = rid


def with_correlation_hook(event_hooks: Any = None) -> dict[str, list[Any]]:
    """Merge :func:`stamp_correlation` into a caller's ``event_hooks`` mapping.

    Kept separate from the client builder so the merge (rather than a clobber) is
    testable on its own, and so a caller that already has request hooks keeps them.
    """
    hooks: dict[str, list[Any]] = {k: list(v) for k, v in (event_hooks or {}).items()}
    hooks.setdefault("request", []).append(stamp_correlation)
    return hooks
