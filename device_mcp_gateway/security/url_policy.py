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
import socket
from urllib.parse import urlparse

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
