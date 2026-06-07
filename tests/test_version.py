# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Version is single-sourced from the package (S2 finding F12)."""

import device_mcp_gateway.main as gw_main
from device_mcp_gateway import __version__
from fastapi.testclient import TestClient


def test_app_version_matches_package():
    assert gw_main.app.version == __version__


def test_health_reports_package_version():
    client = TestClient(gw_main.app)
    assert client.get("/health").json()["version"] == __version__
