# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Outbound URL policy — SSRF guard for device target URLs (Tier-0 F-02/F-29).

A device's ``base_url``/``spec_url`` are operator-supplied and fetched server-side
(reachability, spec discovery, tool calls). Without a policy a caller with
``devices:write`` can point a device at cloud metadata (169.254.169.254), loopback,
or internal RFC-1918 ranges and turn the gateway into an SSRF proxy.

``validate_target_url`` blocks non-http(s) schemes, ports carrying a non-HTTP service
(``security.allowed_target_ports``), and any host that resolves to a private/loopback/
link-local/reserved address. Set ``security.allow_private_targets: true`` (config) for a
trusted internal device fleet to allow private targets.

Validation and connection must agree on the address, or the check is advisory: the guard
resolves the host, then httpx used to resolve it *again* at connect time, and a 0-TTL
alternating record could pass the first lookup and connect on the second. ``SsrfGuardTransport``
therefore pins the validated address through to connect (Host/SNI preserved), so what was
checked is what gets dialled.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

_ALLOWED_SCHEMES = {"http", "https"}

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Ports carrying a NON-HTTP wire protocol (third-party review item 9). The gateway only ever
# speaks HTTP to a target, so pointing it at one of these can't be a legitimate device —
# it can only be a port scan or an attempt to smuggle a payload into another protocol via
# a crafted request line/headers.
#
# This is deliberately a denylist rather than the "80/443 only" allowlist the review
# suggested: this is a *device* gateway, and real fleets live on 8000/8080/8443 (as do
# this project's own documented examples). An 80/443 default would refuse most existing
# deployments on upgrade while adding little — the dangerous targets are the non-HTTP
# services below, not port 8080. Operators wanting the strict posture set
# ``security.allowed_target_ports`` explicitly, which replaces this list with an allowlist.
#
# 2375/2376 are the exception that proves the rule: they *are* HTTP, but an unauthenticated
# Docker daemon is a direct container-escape-to-RCE pivot, so they are refused by default.
_BLOCKED_TARGET_PORTS = frozenset(
    {
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        110,  # POP3
        135,  # MSRPC
        139,  # NetBIOS
        143,  # IMAP
        389,  # LDAP
        445,  # SMB
        465,  # SMTPS
        587,  # SMTP submission
        636,  # LDAPS
        993,  # IMAPS
        995,  # POP3S
        1433,  # MSSQL
        2049,  # NFS
        2375,  # Docker daemon (plain HTTP — RCE pivot)
        2376,  # Docker daemon (TLS)
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        11211,  # memcached
        27017,  # MongoDB
    }
)


class UrlPolicyError(ValueError):
    """Raised when a target URL is rejected by the SSRF policy."""


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Block addresses that should never be reachable from a device target URL.

    IPv4-mapped IPv6 literals (``::ffff:169.254.169.254``, ``::ffff:127.0.0.1``) are
    normalised to the embedded IPv4 first, so the private/loopback/link-local checks apply
    to the real destination rather than the IPv6 wrapper (M-2). Modern CPython already
    reports the whole ``::ffff:0:0/96`` range as reserved, but normalising makes the intent
    explicit and keeps the guard correct independent of interpreter version.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def _check_port(parsed: Any, allowed_ports: set[int] | None) -> None:
    """Enforce the outbound port policy (review item 9).

    ``allowed_ports`` set  → strict allowlist (an operator opted in; the denylist is not
    also consulted, so they can deliberately re-open e.g. 22 if they mean to).
    ``allowed_ports`` None → the default non-HTTP-service denylist.
    """
    try:
        port = parsed.port
    except ValueError as exc:  # out of range — urlparse raises on .port access
        raise UrlPolicyError(f"target URL has an invalid port: {exc}") from exc
    if port is None:
        port = _DEFAULT_PORTS.get(parsed.scheme, 80)

    if allowed_ports is not None:
        if port not in allowed_ports:
            raise UrlPolicyError(
                f"target port {port} is not in security.allowed_target_ports " f"({sorted(allowed_ports)})"
            )
        return
    if port in _BLOCKED_TARGET_PORTS:
        raise UrlPolicyError(
            f"target port {port} carries a non-HTTP service and is refused — the gateway only "
            "speaks HTTP to a device, so this can only be a port scan or protocol smuggling. "
            "Set security.allowed_target_ports to override if this really is an HTTP endpoint."
        )


def validate_target_url(url: str, *, allow_private: bool = False, allowed_ports: set[int] | None = None) -> None:
    """Raise UrlPolicyError if ``url`` is not a safe outbound device target.

    Checks scheme (http/https only), the port policy, and — unless allow_private — resolves
    the host and blocks if *any* resolved address is private/loopback/link-local/reserved
    (so a hostname that resolves to an internal IP is caught, not just IP literals).
    """
    resolve_validated_target(url, allow_private=allow_private, allowed_ports=allowed_ports)


def resolve_validated_target(
    url: str, *, allow_private: bool = False, allowed_ports: set[int] | None = None
) -> str | None:
    """Validate ``url`` and return the single address that was checked, for pinning.

    Returns the address the caller should actually connect to, or ``None`` when there is
    nothing to pin — an IP literal (no DNS, so no race) or ``allow_private`` (resolution
    is skipped entirely). Every resolved address must pass the policy; the first is
    returned, so the address that was *checked* is the address that gets *dialled*.
    """
    if not url or not url.strip():
        raise UrlPolicyError("empty target URL")
    parsed = urlparse(url.strip())
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UrlPolicyError(f"unsupported URL scheme '{parsed.scheme}' (allowed: http, https)")
    host = parsed.hostname
    if not host:
        raise UrlPolicyError("target URL has no host")
    # The port policy is independent of address policy: allow_private opens internal
    # ADDRESSES, not internal SSH, so this is checked before the allow_private short-circuit.
    _check_port(parsed, allowed_ports)
    if allow_private:
        return None

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        # An IP literal still has to pass the address policy — it just needs no DNS, so
        # there is no second resolution to race and nothing to pin.
        if _ip_is_blocked(literal):
            raise UrlPolicyError(
                f"target address {host} is blocked. Internal/loopback/link-local targets are "
                "refused; set security.allow_private_targets: true to allow them."
            )
        return None

    # Ordered + deduped: every address is checked, and the first survivor is what we pin.
    addrs: list[str] = []
    try:
        for res in socket.getaddrinfo(host, None):
            a = str(res[4][0])
            if a not in addrs:
                addrs.append(a)
    except socket.gaierror as exc:
        raise UrlPolicyError(f"cannot resolve host '{host}': {exc}") from exc

    pinned: str | None = None
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
        if pinned is None:
            pinned = a
    return pinned


def resolve_allowed_ports(cfg: dict[str, Any]) -> set[int] | None:
    """The effective ``security.allowed_target_ports``, or None to use the default denylist.

    An empty/absent list means "no explicit allowlist" — the non-HTTP-service denylist
    applies. A non-empty list replaces it with a strict allowlist.
    """
    raw = cfg.get("security", {}).get("allowed_target_ports") or []
    ports = {int(p) for p in raw}
    return ports or None


def resolve_allow_private(cfg: dict[str, Any]) -> bool:
    """The effective allow-private-targets setting: ``security.allow_private_targets``
    (config) OR the ``MCP_ALLOW_PRIVATE_TARGETS`` env override. Centralised so every
    server-side fetch path agrees with the gateway's register/PUT check (F-02)."""
    if bool(cfg.get("security", {}).get("allow_private_targets", False)):
        return True
    return os.getenv("MCP_ALLOW_PRIVATE_TARGETS", "").lower() in ("1", "true", "yes")


class SsrfGuardTransport(httpx.AsyncBaseTransport):
    """Re-applies the SSRF policy to *every* outbound hop, and pins what it validated.

    ``httpx`` follows 3xx redirects internally without re-consulting the caller, so a
    target that passes ``validate_target_url`` at registration can still 302 to
    ``http://169.254.169.254/...`` or an RFC-1918 host and be fetched (F-02/F-29). By
    validating inside the transport — which httpx invokes once per hop — a redirect to
    a blocked address is rejected at the hop instead of blindly followed.

    Validation alone was not enough, though. The guard resolved the host itself, then httpx
    resolved it **again** when it connected — two lookups, and a 0-TTL alternating record
    could pass the first and connect on the second (DNS-rebinding TOCTOU, review item 5).
    Checking more often does not close that window; the checked address has to *be* the
    dialled one. So the validated address is substituted into the URL and the request goes
    out pinned, with no hostname left for httpx to re-resolve.

    ``Host`` and ``sni_hostname`` carry the original name, so virtual hosting still works
    and TLS still verifies against the real hostname rather than the IP (httpcore uses
    ``sni_hostname`` for both the SNI extension and the certificate hostname check).
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        *,
        allow_private: bool,
        allowed_ports: set[int] | None = None,
    ) -> None:
        self._inner = inner
        self._allow_private = allow_private
        self._allowed_ports = allowed_ports

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            pinned_ip = resolve_validated_target(
                str(request.url),
                allow_private=self._allow_private,
                allowed_ports=self._allowed_ports,
            )
        except UrlPolicyError as exc:
            raise UrlPolicyError(f"blocked outbound request to {request.url}: {exc}") from exc
        if pinned_ip is not None:
            request = _pin_request(request, pinned_ip)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def _pin_request(request: httpx.Request, ip: str) -> httpx.Request:
    """A copy of ``request`` aimed at ``ip``, with the original name kept for Host/SNI.

    Builds a NEW request rather than mutating in place: httpx resolves a relative redirect
    ``Location`` against the request URL it gets back, so rewriting the caller's object
    would make the next hop resolve against a bare IP and quietly change redirect
    semantics. The original is left untouched for that logic to use.
    """
    original_host = request.url.host
    headers = request.headers.copy()
    # httpx already derived Host (with the non-default port) from the original URL; keep
    # that value so the origin sees the name it expects, not the address we dialled.
    headers["Host"] = request.headers.get("Host", original_host)
    extensions = dict(request.extensions)
    extensions.setdefault("sni_hostname", original_host)
    return httpx.Request(
        method=request.method,
        url=request.url.copy_with(host=ip),  # brackets IPv6 for us; port/path/query survive
        headers=headers,
        stream=request.stream,
        extensions=extensions,
    )


def build_guarded_client(
    *,
    verify: Any = True,
    allow_private: bool = False,
    allowed_ports: set[int] | None = None,
    follow_redirects: bool = True,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` whose every request hop is checked against the SSRF policy.

    Use for all server-side fetches of operator-supplied URLs — spec discovery,
    reachability, OAuth2 token fetch, and device tool-call dispatch — so workers and the
    gateway share one egress guard rather than relying on a single front-door check
    (closes the "workers never call the URL policy" gap and the redirect-follow bypass).

    ``follow_redirects=False`` is for the tool-call dispatch hot path: redirects are NOT
    followed there (httpx leaks custom auth headers across a cross-origin redirect — it
    only strips ``Authorization``), but the guard still re-validates the target host on
    every call, so a registered device that later resolves to an internal address is caught
    at dispatch time rather than only at registration. Because the validated address is
    pinned through to connect (see :class:`SsrfGuardTransport`), that holds for a *racing*
    rebind too, not only a persistent one."""
    inner = httpx.AsyncHTTPTransport(verify=verify)
    transport = SsrfGuardTransport(inner, allow_private=allow_private, allowed_ports=allowed_ports)
    return httpx.AsyncClient(transport=transport, follow_redirects=follow_redirects, **kwargs)
