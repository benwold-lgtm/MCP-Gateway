# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Shared spec-translation process pool for the worker.

``runner`` (spawn path) and ``health`` (spec-poll path) each used to create
their own 2-process ``ProcessPoolExecutor``, and only health's was reaped at
interpreter exit (RC-5) — so a worker ran four translation processes and leaked
two of them on shutdown. One pool, one atexit hook, shared by both.
"""

from __future__ import annotations

import atexit
from concurrent.futures import ProcessPoolExecutor
from typing import Any

_spec_executor = ProcessPoolExecutor(max_workers=2)


def _shutdown_spec_executor() -> None:
    """Reap the spec-translation worker processes at interpreter exit (RC-5)."""
    _spec_executor.shutdown(wait=False)


atexit.register(_shutdown_spec_executor)


def _translate_spec_sync(spec: dict, hostname: str) -> Any:
    from device_mcp_gateway.core.translator import SpecTranslator

    return SpecTranslator().translate(spec, hostname)
