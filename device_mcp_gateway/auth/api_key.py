"""API Key authentication handler."""

from .base import AbstractAuth


class ApiKeyAuth(AbstractAuth):
    """API Key authentication via custom header."""

    def __init__(self, api_key: str, header_name: str = "X-API-Key"):
        self.api_key = api_key
        self.header_name = header_name

    def get_headers(self) -> dict[str, str]:
        return {self.header_name: self.api_key}
