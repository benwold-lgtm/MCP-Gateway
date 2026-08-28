# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Configuration for the catalog service (ADR-0020 §7).

Flat, env-driven, loaded once at startup — the same shape `device-mcp-gateway-ui`'s BFF
`config.py` uses, not the gateway's YAML+env `cfg.py`, because this service has no analogue
of the gateway's per-device runtime config: everything here is "where is my database" and
"which credential belongs to which caller."

Since ADR-0020 §7a there are **two caller classes** (see `auth.py`): one privileged provider
credential, and one credential per tenant console. The caller table is config, so a
misconfigured one is refused at startup rather than resolved at request time — see
`CatalogAuthConfigError`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


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


class CatalogAuthConfigError(RuntimeError):
    """The caller table is malformed. **Always fatal**, never degraded-but-serving.

    Deliberately unlike a database that is down, which ADR-0020 §7 requires to be a *named
    condition* the service keeps running to report. An unreadable database makes the catalog
    unable to answer; an ambiguous caller table makes it answer *as the wrong caller*, which
    is not a lesser version of working. This is the gateway's `BreakGlassConfigError`
    reasoning applied one service along: "a misconfigured break-glass entry is not a weaker
    version of a working one — it is an entry that would authenticate somebody the audit
    cannot name."
    """


def _parse_tenant_tokens(raw: str, provider_token: str) -> dict[str, str]:
    """Parse ``{"<tenant_id>": "<token>"}`` into the ``token -> tenant_id`` map `auth.py`
    resolves against. Operators write it tenant-first because that is how they think about
    provisioning one; lookup needs the inverse.

    Every failure below is fatal rather than skipped, because each one is a way for a
    credential to end up meaning something other than what the operator wrote:

    * a token shared with the provider would silently promote a tenant to full curation
      authority — the exact failure §7a exists to close;
    * a token shared between two tenants makes "the tenant is read from the credential"
      unanswerable, and any tie-break here would be the silent precedence rule §4b refuses;
    * an empty tenant id or token is an omitted field, and this project's settled instinct
      is that an omitted field must not quietly produce the behaviour an ADR forbids.
    """
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise CatalogAuthConfigError(f"CATALOG_TENANT_TOKENS is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CatalogAuthConfigError("CATALOG_TENANT_TOKENS must be a JSON object of {tenant_id: token}")

    by_token: dict[str, str] = {}
    for tenant_id, token in parsed.items():
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise CatalogAuthConfigError("CATALOG_TENANT_TOKENS has an entry with an empty tenant id")
        if not isinstance(token, str) or not token.strip():
            raise CatalogAuthConfigError(f"CATALOG_TENANT_TOKENS entry {tenant_id!r} has an empty token")
        tenant_id, token = tenant_id.strip(), token.strip()
        if provider_token and token == provider_token:
            raise CatalogAuthConfigError(
                f"CATALOG_TENANT_TOKENS entry {tenant_id!r} reuses the provider's own token. Refusing to "
                "start — that credential would authenticate as the provider, which is the cross-tenant "
                "authority ADR-0020 §7a exists to remove."
            )
        if token in by_token:
            raise CatalogAuthConfigError(
                f"CATALOG_TENANT_TOKENS gives tenants {by_token[token]!r} and {tenant_id!r} the same token. "
                "Refusing to start — the tenant is read from the credential (ADR-0020 §7a), and a shared "
                "token makes that question have two answers."
            )
        by_token[token] = tenant_id
    return by_token


@dataclass(frozen=True)
class Settings:
    host: str = "0.0.0.0"  # nosec B104 — bind-all intended in containers
    port: int = 8100

    # Postgres per ADR-0020 20.1 ("resolved: PostgreSQL"). No embedded/SQLite mode: unlike
    # the gateway, this service has no single-operator/Lite deployment target — a catalog
    # only exists where there is a provider plane to curate it, and ADR-0025 already
    # designs this store's durability story around Postgres specifically (WAL/PITR).
    database_url: str = ""

    # The PROVIDER's credential: the privileged caller class (ADR-0020 §7a) — curate device
    # types, assign and revoke, read everything. Named `api_token` still because it is the
    # same credential the provider console's `CatalogClient` already holds; what changed in
    # §7a is that it is no longer the *only* one, and no longer belongs in a tenant's BFF.
    api_token: str = ""

    # `token -> tenant_id` for the tenant caller class. One credential per tenant console,
    # each admitting exactly the device types assigned to that tenant and claims recorded
    # for it. The map is keyed by token because that is the lookup `auth.py` performs; the
    # operator-facing shape is the inverse (see `_parse_tenant_tokens`).
    #
    # Empty is the correct configuration for a provider plane whose tenants do not read the
    # catalog directly, and it fails closed: with no entry, no tenant credential exists to
    # present, so every caller must be the provider.
    tenant_tokens: dict[str, str] = field(default_factory=dict)


def load_settings() -> Settings:
    provider_token = _secret("CATALOG_API_TOKEN", "CATALOG_API_TOKEN_FILE")
    return Settings(
        host=os.getenv("CATALOG_HOST", "0.0.0.0"),  # nosec B104 — bind-all intended in containers
        port=int(os.getenv("CATALOG_PORT", "8100")),
        database_url=os.getenv("CATALOG_DATABASE_URL", ""),
        api_token=provider_token,
        # Same `*_FILE` convention as every other secret here: the JSON map is a mounted
        # Secret, never a ConfigMap value or a command line, since it holds every tenant's
        # credential in one document.
        tenant_tokens=_parse_tenant_tokens(
            _secret("CATALOG_TENANT_TOKENS", "CATALOG_TENANT_TOKENS_FILE"), provider_token
        ),
    )
