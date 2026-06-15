# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Device MCP Gateway - Universal API-to-MCP Translation Layer
"""

__version__ = "0.1.0"

# External REST API version. All device-management endpoints are served under
# this prefix (e.g. /v1/devices). Operational probes (/health, /readyz) and the
# Prometheus scrape endpoint are intentionally unversioned. Bump this prefix —
# and dual-mount the old one for a deprecation window — when the API contract
# breaks in a backward-incompatible way.
API_V1_PREFIX = "/v1"
