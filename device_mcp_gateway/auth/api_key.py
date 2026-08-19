# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""API Key authentication handler."""

from __future__ import annotations

from typing import Any

from device_mcp_gateway.credentials import CredentialRef

from .base import AbstractAuth, AuthMaterial, CredentialNotBound, exclusive_secret

# Where the key is placed on the outbound request (F-43).
_LOCATIONS = ("header", "query", "cookie")
_DEFAULT_NAMES = {"header": "X-API-Key", "query": "api_key", "cookie": "api_key"}


class ApiKeyAuth(AbstractAuth):
    """API key auth, placeable in a header, query param, or cookie (F-43).

    ``value_prefix`` prepends a scheme to the value, so a bearer-style key is just
    ``location="header"``, ``name="Authorization"``, ``value_prefix="Bearer "``.
    The legacy ``header_name`` argument still works and maps to a header-located
    key, so existing device configs keep parsing.
    """

    def __init__(
        self,
        api_key: str | None = None,
        header_name: str = "X-API-Key",
        *,
        location: str = "header",
        name: str | None = None,
        value_prefix: str = "",
        credential_ref: str | None = None,
    ):
        if location not in _LOCATIONS:
            raise ValueError(f"api_key location must be one of {_LOCATIONS}, got {location!r}")
        # ADR-0018: inline or by reference, never both and never neither. Checked here rather
        # than at the route so every construction path — registration, a restore, a worker
        # rehydrating from the store — gets the same answer.
        exclusive_secret(api_key, credential_ref, field="api_key")
        if credential_ref is not None:
            # Parsed at construction so a malformed reference is a registration error, not a
            # dispatch-time surprise on a device that looked fine when it was added.
            CredentialRef.parse(credential_ref)
        self.credential_ref = credential_ref
        self.api_key = api_key
        self.location = location
        # name precedence: explicit name > legacy header_name (header only) > per-location default.
        if name:
            self.name = name
        elif location == "header" and header_name:
            self.name = header_name
        else:
            self.name = _DEFAULT_NAMES[location]
        self.value_prefix = value_prefix
        # Kept so legacy readers of `.header_name` still work for header-located keys.
        self.header_name = self.name if location == "header" else header_name

    @property
    def _value(self) -> str:
        if self.api_key is None:
            # By-reference and not yet bound. Failing here beats sending
            # "Bearer None" upstream, which returns 401 and reads as a wrong credential.
            raise CredentialNotBound(
                f"api key for {self.credential_ref!r} has not been resolved; "
                "the dispatch path must call bind() before applying auth"
            )
        value = f"{self.value_prefix}{self.api_key}"
        if self.location == "header":
            # HTTP headers are latin-1 on the wire, so a non-ASCII credential fails at
            # encoding — and the exception httpx raises names neither the device, the
            # credential, nor the header. Measured on a live cluster, where a secret
            # containing two Cyrillic characters surfaced only as
            # "'ascii' codec can't encode characters in position 14-15" and then as
            # "No spec available", which points at the upstream rather than the secret.
            #
            # Only headers are constrained: a query or cookie value is encoded by the
            # transport, so those placements keep accepting any text.
            try:
                value.encode("latin-1")
            except UnicodeEncodeError as exc:
                where = f"reference {self.credential_ref!r}" if self.credential_ref else "inline api_key"
                raise CredentialNotBound(
                    f"the credential from {where} contains characters that cannot be sent in an "
                    f"HTTP header (position {exc.start}); headers are latin-1. Store an "
                    "ASCII-safe value, or place the key in a query parameter or cookie."
                ) from exc
        return value

    async def bind(self, resolver: Any) -> None:
        """Resolve ``credential_ref`` into the live key for this dispatch.

        The resolved value is held on the instance, which is per-pod and per-request in the
        paths that use it — never written back to the registry. ``ReferenceInvalid`` and
        ``StoreUnavailable`` propagate unchanged, because ADR-0018 §7's whole point is that
        the caller can tell a bad reference from a store outage.
        """
        if self.credential_ref is None:
            return
        self.api_key = await resolver.resolve(CredentialRef.parse(self.credential_ref))

    def configure_credentials(self, resolver: Any | None) -> None:
        self._resolver = resolver

    async def _ensure_bound(self) -> None:
        """Resolve the reference if this handler carries one.

        **Resolved on every dispatch, deliberately, for now.** ADR-0018 makes the resolution
        cache an explicit TTL decision with its own metrics, and a cache added here without
        one would be an implicit unbounded copy held for the pod's lifetime — the durable copy
        §1 draws a line against. The cache arrives with its instrumentation, not before it.
        """
        if self.credential_ref is None:
            return
        resolver = getattr(self, "_resolver", None)
        if resolver is not None:
            await self.bind(resolver)
            return
        if self.api_key is None:
            # Fail closed, naming which of the two things is wrong: the device wants a
            # reference resolved and this deployment has no resolver at all. Distinguishing
            # this from "the store said no" matters — they send an operator to different
            # systems, which is the same reasoning as §7's two failure kinds one level up.
            raise CredentialNotBound(
                f"device credential {self.credential_ref!r} has not been resolved: this handler was "
                "never given a credential resolver. Either the deployment has none configured "
                "(gateway.credentials.root / MCP_CREDENTIAL_ROOT), or this dispatch path predates "
                "the ADR-0018 wiring — which is what a replica mid-rolling-restart looks like."
            )
        # Already bound out of band by a caller that resolved explicitly. Left usable rather
        # than re-refused, so `bind()` stays meaningful on its own.

    async def get_headers(self) -> dict[str, str]:
        # Header-only view (back-compat); empty when the key lives in a query/cookie.
        await self._ensure_bound()
        return {self.name: self._value} if self.location == "header" else {}

    async def apply(self) -> AuthMaterial:
        await self._ensure_bound()
        if self.location == "query":
            return AuthMaterial(params={self.name: self._value})
        if self.location == "cookie":
            return AuthMaterial(cookies={self.name: self._value})
        return AuthMaterial(headers={self.name: self._value})

    def to_dict(self) -> dict[str, Any]:
        # A by-reference handler serialises its reference and NOT the material it may have
        # resolved a moment ago. Emitting a bound value would write the secret back into the
        # registry on the next update — quietly undoing ADR-0018 for that device.
        if self.credential_ref is not None:
            return {
                "type": "api_key",
                "credential_ref": self.credential_ref,
                "location": self.location,
                "name": self.name,
                "value_prefix": self.value_prefix,
                "header_name": self.header_name,
            }
        return {
            "type": "api_key",
            "api_key": self.api_key,
            "location": self.location,
            "name": self.name,
            "value_prefix": self.value_prefix,
            # Legacy field so an older worker/reader can still place a header key.
            "header_name": self.header_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApiKeyAuth":
        return cls(
            api_key=data.get("api_key"),
            credential_ref=data.get("credential_ref"),
            header_name=data.get("header_name", "X-API-Key"),
            location=data.get("location", "header"),
            name=data.get("name"),
            value_prefix=data.get("value_prefix", ""),
        )
