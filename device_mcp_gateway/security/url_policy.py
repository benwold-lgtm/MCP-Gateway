# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Outbound URL policy — SSRF guard for device target URLs (Tier-0 F-02/F-29).

A device's ``base_url``/``spec_url`` are operator-supplied and fetched server-side
(reachability, spec discovery, tool calls). Without a policy a caller with
``devices:write`` can point a device at cloud metadata (169.254.169.254), loopback,
or internal RFC-1918 ranges and turn the gateway into an SSRF proxy.

``validate_target_url`` blocks non-http(s) schemes and any host that resolves to a
private/loopback/link-local/reserved address. Set ``security.allow_private_targets:
true`` (config) for a trusted internal device fleet to allow private targets.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

_ALLOWED_SCHEMES = {"http", "https"}


class UrlPolicyError(ValueError):
    """Raised when a target URL is rejected by the SSRF policy."""


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Block addresses that should never be reachable from a device target URL."""
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def validate_target_url(url: str, *, allow_private: bool = False) -> None:
    """Raise UrlPolicyError if ``url`` is not a safe outbound device target.

    Checks scheme (http/https only) and — unless allow_private — resolves the host
    and blocks if *any* resolved address is private/loopback/link-local/reserved
    (so a hostname that resolves to an internal IP is caught, not just IP literals).
    """
    if not url or not url.strip():
        raise UrlPolicyError("empty target URL")
    parsed = urlparse(url.strip())
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UrlPolicyError(f"unsupported URL scheme '{parsed.scheme}' (allowed: http, https)")
    host = parsed.hostname
    if not host:
        raise UrlPolicyError("target URL has no host")
    if allow_private:
        return

    addrs: set[str] = set()
    try:
        addrs.add(str(ipaddress.ip_address(host)))  # IP literal
    except ValueError:
        try:
            for res in socket.getaddrinfo(host, None):
                addrs.add(str(res[4][0]))
        except socket.gaierror as exc:
            raise UrlPolicyError(f"cannot resolve host '{host}': {exc}") from exc

    for a in addrs:
        # Strip an IPv6 scope id (e.g. 'fe80::1%eth0') before parsing.
        try:
            ip = ipaddress.ip_address(a.split("%", 1)[0])
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise UrlPolicyError(
                f"target host '{host}' resolves to a blocked address ({a}). Internal/loopback/"
                "link-local targets are refused; set security.allow_private_targets: true to allow them."
            )


def resolve_allow_private(cfg: dict[str, Any]) -> bool:
    """The effective allow-private-targets setting: ``security.allow_private_targets``
    (config) OR the ``MCP_ALLOW_PRIVATE_TARGETS`` env override. Centralised so every
    server-side fetch path agrees with the gateway's register/PUT check (F-02)."""
    if bool(cfg.get("security", {}).get("allow_private_targets", False)):
        return True
    return os.getenv("MCP_ALLOW_PRIVATE_TARGETS", "").lower() in ("1", "true", "yes")


class SsrfGuardTransport(httpx.AsyncBaseTransport):
    """Re-applies the SSRF policy to *every* outbound hop, including each redirect.

    ``httpx`` follows 3xx redirects internally without re-consulting the caller, so a
    target that passes ``validate_target_url`` at registration can still 302 to
    ``http://169.254.169.254/...`` or an RFC-1918 host and be fetched (F-02/F-29). By
    validating inside the transport — which httpx invokes once per hop — a redirect to
    a blocked address is rejected at the hop instead of blindly followed.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport, *, allow_private: bool) -> None:
        self._inner = inner
        self._allow_private = allow_private

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            validate_target_url(str(request.url), allow_private=self._allow_private)
        except UrlPolicyError as exc:
            raise UrlPolicyError(f"blocked outbound request to {request.url}: {exc}") from exc
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def build_guarded_client(*, verify: Any = True, allow_private: bool = False, **kwargs: Any) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` whose every request hop (initial + redirects) is checked
    against the SSRF policy. Use for all server-side fetches of operator-supplied device
    URLs — spec discovery and reachability — so workers and the gateway share one egress
    guard rather than relying on a single front-door check (closes the "workers never
    call the URL policy" gap and the redirect-follow bypass)."""
    inner = httpx.AsyncHTTPTransport(verify=verify)
    transport = SsrfGuardTransport(inner, allow_private=allow_private)
    return httpx.AsyncClient(transport=transport, follow_redirects=True, **kwargs)
