"""OAuth 2.0 Client Credentials flow with JWT handling."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
from loguru import logger

from .base import AbstractAuth


@dataclass
class OAuth2Auth(AbstractAuth):
    """OAuth2 authentication handler with automatic token refresh."""

    token_endpoint: str
    client_id: str
    client_secret: str
    scopes: list[str] = None
    refresh_before_expiry: int = 300

    def __post_init__(self):
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expiry: float = 0.0
        self._scopes = self.scopes or ["read"]

    async def ensure_token(self) -> None:
        if self._access_token and time.time() < self._token_expiry - self.refresh_before_expiry:
            return
        await self._fetch_token()

    async def _fetch_token(self) -> None:
        async with httpx.AsyncClient(timeout=10) as client:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": " ".join(self._scopes),
            }
            try:
                resp = await client.post(self.token_endpoint, data=data)
                resp.raise_for_status()
                tokens = resp.json()
                self._access_token = tokens.get("access_token")
                self._refresh_token = tokens.get("refresh_token")
                expires_in = int(tokens.get("expires_in", 3600))
                self._token_expiry = time.time() + expires_in
                logger.info("OAuth2 token retrieved successfully")
            except Exception as e:
                logger.error(f"OAuth2 token fetch failed: {e}")
                raise

    def get_headers(self) -> dict[str, str]:
        if not self._access_token:
            raise RuntimeError("Token not initialized. Call ensure_token() first.")
        return {"Authorization": f"Bearer {self._access_token}"}
