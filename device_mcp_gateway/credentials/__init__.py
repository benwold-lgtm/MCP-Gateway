# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Credential resolution (ADR-0018) — the registry holds a reference, never a secret."""

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
