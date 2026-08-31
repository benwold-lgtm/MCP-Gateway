# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The catalog's first encryption key (ADR-0024 §11).

Everything else this service stores it only ever **recognises** — an issued tenant credential is
a hash, and that is exactly right for a value nobody needs back. The provider's own credential
for a tenant's gateway is the one exception: the provider *presents* it on every support
request, so it has to be readable again, which makes it encryption rather than hashing. The same
distinction ADR-0020 §4b drew for a curated spec and §10 drew for the tenant's catalog
credential.

This is real new operational surface in a service whose simplicity has been defended twice, and
§11 accepts it explicitly: the alternative keeps ADR-0024 §4's `gateway_token_file` convention —
a path to a file someone places out of band — which relocates the manual step §11 exists to
remove rather than removing it.

**With no key configured the value is stored in plaintext**, and startup says so. That mirrors
the gateway's own `CredentialCodec` rather than inventing a second convention for "encryption is
off", and it keeps a lab or single-tenant deployment runnable without key management. It is a
documented trade-off, not a silent one.
"""

from __future__ import annotations

from typing import Optional

from loguru import logger


class CredentialCodec:
    """Fernet encryption for the one stored value that must be readable again.

    Deliberately a small local class rather than an import from the gateway package: the catalog
    is a separate component with its own dependency tree (`tool_diff.py` already refused that
    import for the same reason), and pulling in the gateway to get one wrapper would undo
    ADR-0020 §7's separation for a convenience.
    """

    def __init__(self, key: str = "") -> None:
        self._fernet = None
        if key:
            from cryptography.fernet import Fernet

            # A malformed key raises here, at startup, rather than at the first enrolment.
            # Failing loudly on a key that cannot work is the same instinct `config.py` applies
            # to an ambiguous caller table: a credential store that silently fell back to
            # plaintext would be the worst of both.
            self._fernet = Fernet(key.encode())
        else:
            logger.warning(
                "catalog: CATALOG_SECRET_KEY is not set — the provider's per-tenant gateway "
                "credentials are stored as PLAINTEXT (ADR-0024 §11). Generate one: python -c "
                '"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, plaintext: str) -> str:
        if self._fernet is None or not plaintext:
            return plaintext
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, stored: str) -> str:
        if self._fernet is None or not stored:
            return stored
        return self._fernet.decrypt(stored.encode()).decode()


def codec_for(state: object) -> CredentialCodec:
    existing: Optional[CredentialCodec] = getattr(state, "codec", None)
    return existing or CredentialCodec()
