# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for spec-ingestion / translation bounds (F-09).

A device serves its own OpenAPI document; a hostile or accidentally-huge spec
must not exhaust memory at fetch time or starve the shared spec-translation
process pool. These cover the three controls: response-size rejection,
operation-count rejection (enforced inside translate()), and the translation
wall-clock timeout.
"""

import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from device_mcp_gateway.core.spec_limits import (
    SpecTooLargeError,
    enforce_operation_count,
    enforce_response_size,
    fetched_spec_or_none,
    run_translation,
)
from device_mcp_gateway.core.translator import SpecTranslator


def _resp(body: bytes, *, status=200, content_length=None):
    headers = {"content-type": "application/json"}
    if content_length is not None:
        headers["content-length"] = str(content_length)
    return httpx.Response(status_code=status, content=body, headers=headers)


# --- response size -----------------------------------------------------------


def test_response_size_rejects_oversized_body():
    with pytest.raises(SpecTooLargeError):
        enforce_response_size(_resp(b"x" * 2048), max_bytes=1024)


class _HeaderStub:
    """Minimal response stand-in: httpx.Response recomputes Content-Length to match
    the body, so a *declared* oversized Content-Length (as a streaming server would
    send) can only be exercised with a stub exposing the header verbatim."""

    def __init__(self, content: bytes, content_length: int):
        self.content = content
        self.headers = {"content-length": str(content_length)}


def test_response_size_rejects_on_declared_content_length():
    # A large Content-Length is rejected up front, before the body is consulted.
    with pytest.raises(SpecTooLargeError):
        enforce_response_size(_HeaderStub(b"{}", 10_000_000), max_bytes=1024)


def test_response_size_allows_within_limit():
    enforce_response_size(_resp(b"{}"), max_bytes=1024)  # no raise


def test_response_size_disabled_when_limit_zero():
    enforce_response_size(_resp(b"x" * 5000), max_bytes=0)  # 0 => unbounded, no raise


def test_fetched_spec_or_none_parses_200_and_skips_non_200():
    assert fetched_spec_or_none(_resp(b'{"openapi": "3.0.0"}'), max_bytes=1024) == {"openapi": "3.0.0"}
    assert fetched_spec_or_none(_resp(b"{}", status=404), max_bytes=1024) is None


def test_fetched_spec_or_none_raises_when_oversized():
    with pytest.raises(SpecTooLargeError):
        fetched_spec_or_none(_resp(b"y" * 4096), max_bytes=1024)


# --- operation count ---------------------------------------------------------


def _spec_with_n_ops(n):
    methods = ["get", "post", "put", "delete", "patch"]
    paths = {}
    for i in range(n):
        m = methods[i % len(methods)]
        paths[f"/p{i}"] = {m: {"operationId": f"op{i}", "responses": {"200": {"description": "ok"}}}}
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1.0.0"}, "paths": paths}


def test_operation_count_rejects_over_limit():
    with pytest.raises(SpecTooLargeError):
        enforce_operation_count(_spec_with_n_ops(50), max_ops=10)


def test_operation_count_allows_under_limit():
    enforce_operation_count(_spec_with_n_ops(5), max_ops=10)  # no raise


def test_operation_count_ignores_non_method_keys():
    spec = {"paths": {"/p": {"get": {}, "parameters": [], "summary": "x"}}}
    enforce_operation_count(spec, max_ops=1)  # only `get` counts => exactly at limit, no raise


def test_translate_rejects_spec_exceeding_default_operation_cap():
    # End-to-end: translate() is the universal chokepoint and rejects an absurd
    # operation count before the (expensive) validator/per-op work runs, so a
    # huge spec can't monopolise a pool worker. Uses the real default cap (2000).
    from device_mcp_gateway.core.spec_limits import DEFAULT_MAX_OPERATIONS

    big = _spec_with_n_ops(DEFAULT_MAX_OPERATIONS + 1)
    with pytest.raises(SpecTooLargeError):
        SpecTranslator().translate(big, "dev")


def test_translate_accepts_a_normal_spec():
    # Guard against a false-positive bound: a small valid spec still translates.
    manifest = SpecTranslator().translate(_spec_with_n_ops(3), "dev")
    assert len(manifest.tools) == 3


# --- translation timeout -----------------------------------------------------


@pytest.mark.asyncio
async def test_run_translation_times_out_and_raises():
    def _slow():
        time.sleep(1.0)
        return "done"

    with ThreadPoolExecutor(max_workers=1) as ex:
        with pytest.raises(SpecTooLargeError):
            await run_translation(ex, _slow, timeout=0.05, hostname="dev")


@pytest.mark.asyncio
async def test_run_translation_returns_result_within_timeout():
    with ThreadPoolExecutor(max_workers=1) as ex:
        result = await run_translation(ex, lambda: 42, timeout=5.0, hostname="dev")
    assert result == 42
