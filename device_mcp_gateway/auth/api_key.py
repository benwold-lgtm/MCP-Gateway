# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""API Key authentication handler."""

from __future__ import annotations

from typing import Any

from .base import AbstractAuth, AuthMaterial

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
        api_key: str,
        header_name: str = "X-API-Key",
        *,
        location: str = "header",
        name: str | None = None,
        value_prefix: str = "",
    ):
        if location not in _LOCATIONS:
            raise ValueError(f"api_key location must be one of {_LOCATIONS}, got {location!r}")
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
        return f"{self.value_prefix}{self.api_key}"

    async def get_headers(self) -> dict[str, str]:
        # Header-only view (back-compat); empty when the key lives in a query/cookie.
        return {self.name: self._value} if self.location == "header" else {}

    async def apply(self) -> AuthMaterial:
        if self.location == "query":
            return AuthMaterial(params={self.name: self._value})
        if self.location == "cookie":
            return AuthMaterial(cookies={self.name: self._value})
        return AuthMaterial(headers={self.name: self._value})

    def to_dict(self) -> dict[str, Any]:
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
            api_key=data["api_key"],
            header_name=data.get("header_name", "X-API-Key"),
            location=data.get("location", "header"),
            name=data.get("name"),
            value_prefix=data.get("value_prefix", ""),
        )
