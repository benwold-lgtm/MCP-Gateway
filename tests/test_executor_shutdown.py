# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Regression coverage for S1 real-concern RC-5.

The module-level spec-translation ProcessPoolExecutors in registry.server and
worker.health are reaped at interpreter exit via atexit-registered shutdown
functions. These tests exercise the shutdown wiring against a fake executor so
the real (process-global) executors are left intact for the rest of the suite.
"""

import device_mcp_gateway.registry.server as server_mod
import device_mcp_gateway.worker.health as health_mod


class _FakeExecutor:
    def __init__(self):
        self.shutdown_calls = []

    def shutdown(self, wait=True):
        self.shutdown_calls.append(wait)


def test_health_spec_executor_shutdown_is_non_blocking(monkeypatch):
    fake = _FakeExecutor()
    monkeypatch.setattr(health_mod, "_spec_executor", fake)
    health_mod._shutdown_spec_executor()
    assert fake.shutdown_calls == [False]  # wait=False — don't block exit


def test_server_spec_executor_shutdown_is_non_blocking(monkeypatch):
    fake = _FakeExecutor()
    monkeypatch.setattr(server_mod, "_spec_executor", fake)
    server_mod._shutdown_spec_executor()
    assert fake.shutdown_calls == [False]
