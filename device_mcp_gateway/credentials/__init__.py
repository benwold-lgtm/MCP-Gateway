# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Credential resolution (ADR-0018) — the registry holds a reference for the secrets a
tenant provisions.

Scoped deliberately, per ADR-0018 §1a: this covers **operator-provisioned** secrets, where the
tenant is the sole writer of the secret's lifecycle. It does **not** cover credentials the
gateway itself mints — an OAuth2 refresh token rotated mid-exchange has no other writer, so it
is still persisted under ``MCP_SECRET_KEY``. For a device using one, a key compromise carries
the identical risk it did before this design existed.
"""

from .resolver import (
    CredentialRef,
    CredentialResolver,
    MountedFilesResolver,
    ReferenceInvalid,
    ResolverError,
    StoreUnavailable,
    build_resolver,
)

__all__ = [
    "CredentialRef",
    "CredentialResolver",
    "MountedFilesResolver",
    "ReferenceInvalid",
    "ResolverError",
    "StoreUnavailable",
    "build_resolver",
]
