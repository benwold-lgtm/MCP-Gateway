# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Bounds on OpenAPI spec ingestion and translation (F-09).

A device serves its own OpenAPI document, so a hostile or accidentally-huge spec
must not be able to exhaust gateway/worker memory at fetch time or starve the
shared spec-translation process pool. Three small, independent controls:

  * ``enforce_response_size`` — reject a fetched spec whose body exceeds the byte
    ceiling *before* it is JSON-parsed, so an oversized document never reaches the
    parser, cache, or the translation pool. Checks the declared Content-Length
    (cheap, catches honest servers) and the actual bytes read.
  * ``enforce_operation_count`` — checked at the top of ``SpecTranslator.translate``;
    a deterministic cap on the number of operations so even a spec that arrives by
    another path can't generate an unbounded manifest or monopolise a pool worker.
  * ``run_translation`` — wraps the executor submit with a wall-clock timeout so a
    pathological-but-within-bounds spec can't hold the awaiting health/registry loop
    open indefinitely.

All raise ``SpecTooLargeError`` (a ``ValueError``) with an operator-readable message.

Residual (accepted under D-1, single-tenant-per-stack): a malicious chunked response
that omits or lies about Content-Length is still buffered once into ``resp.content``
before the post-read size check rejects it — bounded by a single transfer, never
amplified into the pool or cache. Streaming-read hardening is a possible follow-up.
"""

import asyncio
from concurrent.futures import Executor
from typing import Any, Callable, TypeVar

import httpx
from loguru import logger

# Operations that translate() turns into tools (mirrors translator's method filter).
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"})

# Defaults — overridable via registry config where the value is plumbed through.
DEFAULT_MAX_SPEC_BYTES = 5_000_000  # 5 MB: generous for real specs, fatal to a DoS blob
DEFAULT_MAX_OPERATIONS = 2_000  # an absurd op count => refuse rather than translate
DEFAULT_TRANSLATE_TIMEOUT = 15.0  # seconds a single translation may hold a pool worker

T = TypeVar("T")


class SpecTooLargeError(ValueError):
    """An OpenAPI spec exceeded an ingestion/translation bound (F-09)."""


def enforce_response_size(resp: httpx.Response, *, max_bytes: int = DEFAULT_MAX_SPEC_BYTES) -> None:
    """Raise ``SpecTooLargeError`` if the fetched spec body exceeds ``max_bytes``.

    Checks the declared Content-Length first (rejects honest oversized servers
    without touching the body) then the bytes actually buffered, so the spec is
    rejected before the (more expensive) JSON parse and before it reaches the
    translation pool or cache.
    """
    if max_bytes <= 0:
        return
    declared = resp.headers.get("content-length")
    if declared is not None:
        try:
            declared_int: int | None = int(declared)
        except ValueError:
            declared_int = None  # unparseable header — fall through to the actual-size check
        if declared_int is not None and declared_int > max_bytes:
            raise SpecTooLargeError(f"spec Content-Length {declared} exceeds limit {max_bytes} bytes")
    if len(resp.content) > max_bytes:
        raise SpecTooLargeError(f"spec body {len(resp.content)} exceeds limit {max_bytes} bytes")


def enforce_operation_count(spec: dict, *, max_ops: int = DEFAULT_MAX_OPERATIONS) -> None:
    """Raise ``SpecTooLargeError`` if the spec declares more than ``max_ops`` operations.

    Cheap iteration over ``paths`` × HTTP methods; runs before the per-operation
    translation work so a spec can't be inflated into an unbounded manifest.
    """
    if max_ops <= 0:
        return
    ops = 0
    for methods in spec.get("paths", {}).values():
        if not isinstance(methods, dict):
            continue
        ops += sum(1 for m in methods if isinstance(m, str) and m.upper() in _HTTP_METHODS)
        if ops > max_ops:
            raise SpecTooLargeError(f"spec declares more than {max_ops} operations")


async def run_translation(
    executor: Executor,
    func: Callable[[], T],
    *,
    timeout: float = DEFAULT_TRANSLATE_TIMEOUT,
    hostname: str = "?",
) -> T:
    """Run ``func`` (a translate call) in ``executor`` with a wall-clock backstop.

    ``asyncio.wait_for`` returns control to the awaiting loop on timeout even though
    the pool worker keeps running; combined with the size/op-count bounds — which
    keep each translation cheap — this prevents one spec from wedging the loop while
    the pool drains. Re-raises as ``SpecTooLargeError`` so callers handle one type.
    """
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(loop.run_in_executor(executor, func), timeout=timeout)
    except asyncio.TimeoutError as exc:
        logger.warning(f"Spec translation for {hostname} timed out after {timeout}s — spec rejected (F-09)")
        raise SpecTooLargeError(f"spec translation for {hostname} timed out after {timeout}s") from exc


def fetched_spec_or_none(resp: httpx.Response, *, max_bytes: int = DEFAULT_MAX_SPEC_BYTES) -> dict[str, Any] | None:
    """Size-check a 200 spec response and parse it, else return None.

    Convenience for the fetch sites: returns the parsed dict on a 200 within the
    byte ceiling, ``None`` for a non-200, and raises ``SpecTooLargeError`` when the
    body is too large (so an oversized spec is a loud failure, not a silent skip).
    """
    if resp.status_code != 200:
        return None
    enforce_response_size(resp, max_bytes=max_bytes)
    return resp.json()
