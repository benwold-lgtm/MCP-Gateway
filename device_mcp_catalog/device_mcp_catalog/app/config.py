# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Configuration for the catalog service (ADR-0020 §7).

Flat, env-driven, loaded once at startup — the same shape `device-mcp-gateway-ui`'s BFF
`config.py` uses, not the gateway's YAML+env `cfg.py`, because this service has no analogue
of the gateway's per-device runtime config: everything here is "where is my database" and
"what token authenticates my one caller."
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _secret(env_name: str, file_env: str) -> str:
    """A secret from ``env_name``, or from the file named by ``file_env`` if the var is
    empty (the standard ``*_FILE`` convention, mirroring the BFF's `config.py`) — lets a
    Kubernetes Secret volume mount supply the value without it ever sitting in a ConfigMap
    or a process's command line."""
    value = os.getenv(env_name, "")
    if value:
        return value
    file_path = os.getenv(file_env, "").strip()
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""
    return ""


@dataclass(frozen=True)
class Settings:
    host: str = "0.0.0.0"  # nosec B104 — bind-all intended in containers
    port: int = 8100

    # Postgres per ADR-0020 20.1 ("resolved: PostgreSQL"). No embedded/SQLite mode: unlike
    # the gateway, this service has no single-operator/Lite deployment target — a catalog
    # only exists where there is a provider plane to curate it, and ADR-0025 already
    # designs this store's durability story around Postgres specifically (WAL/PITR).
    database_url: str = ""

    # The one caller this service expects (the console BFF's `CatalogClient`). A single
    # shared token, not a scope model — ADR-0020 phase 1 has exactly one caller, and this
    # project's own established instinct is not to build a permission model with no second
    # caller yet to justify it (see rbac.py's ALL_SCOPES commentary in the gateway repo).
    api_token: str = ""


def load_settings() -> Settings:
    return Settings(
        host=os.getenv("CATALOG_HOST", "0.0.0.0"),  # nosec B104 — bind-all intended in containers
        port=int(os.getenv("CATALOG_PORT", "8100")),
        database_url=os.getenv("CATALOG_DATABASE_URL", ""),
        api_token=_secret("CATALOG_API_TOKEN", "CATALOG_API_TOKEN_FILE"),
    )
