# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""API Key authentication handler."""

from __future__ import annotations
from typing import Any

from .base import AbstractAuth


class ApiKeyAuth(AbstractAuth):
    """API Key authentication via custom header."""

    def __init__(self, api_key: str, header_name: str = "X-API-Key"):
        self.api_key = api_key
        self.header_name = header_name

    async def get_headers(self) -> dict[str, str]:
        return {self.header_name: self.api_key}

    def to_dict(self) -> dict[str, Any]:
        return {"type": "api_key", "api_key": self.api_key, "header_name": self.header_name}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApiKeyAuth":
        return cls(api_key=data["api_key"], header_name=data.get("header_name", "X-API-Key"))
