# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Outbound TLS / mutual-TLS for device calls (F-31).

The gateway and workers make outbound HTTPS calls to device APIs — tool calls
(``DevicePod``), reachability probes and spec fetches (``Registry`` /
``DeviceWorker``), and periodic health checks (``DeviceHealthChecker``). Without
F-31 those calls could only do anonymous server-auth TLS against the public CA
set: the gateway could not present a client certificate to a device that
requires mutual TLS, nor verify a device whose server certificate is signed by a
private CA.

This module turns a ``security.mtls`` config block into a single value suitable
for httpx's ``verify=`` parameter:

    security:
      mtls:
        client_cert: /etc/mcp/tls/client.crt   # PEM; may also contain the key
        client_key:  /etc/mcp/tls/client.key   # PEM private key (omit if combined into client_cert)
        client_key_password: ...               # prefer the env var below over config
        ca_bundle:   /etc/mcp/tls/device-ca.pem # verify device server certs against this CA
        verify: true                           # set false ONLY on a trusted closed test network

The client-key password is read from ``MCP_TLS_CLIENT_KEY_PASSWORD`` in
preference to config, so the secret need not live in the config file (mirrors the
metrics-token resolution in F-36).

Design notes:
  * We return an ``ssl.SSLContext`` (not the deprecated ``cert=`` / string
    ``verify=`` httpx kwargs) so the call sites stay forward-compatible with
    httpx >= 0.28, where passing an SSLContext to ``verify=`` is the supported
    path.
  * When nothing is configured we return ``True`` — httpx's default certifi-based
    server verification — so non-mTLS deployments behave exactly as before.
  * The default trust anchor is certifi (what httpx itself uses), not the OS
    store, so behaviour is identical across hosts unless a ``ca_bundle`` is given.
  * Built contexts are cached by their resolved signature; every device-facing
    client shares one global TLS config today, so this collapses to a single
    context. Per-device certificate overrides (heterogeneous device PKIs) are a
    planned extension — see docs/security-mtls.md.
"""

from __future__ import annotations

import os
import ssl
from typing import Union

import certifi

ENV_KEY_PASSWORD = "MCP_TLS_CLIENT_KEY_PASSWORD"  # nosec B105 — env-var name, not a secret

VerifyValue = Union[ssl.SSLContext, bool]

# Signature -> built verify value. Building an SSLContext loads cert files from
# disk, so cache by the resolved inputs (all device clients share one config).
_CONTEXT_CACHE: dict[tuple, VerifyValue] = {}


def _resolve(mtls_cfg: dict | None) -> dict:
    """Flatten a ``security.mtls`` block, applying the env password override."""
    cfg = mtls_cfg or {}
    resolved = {
        "client_cert": cfg.get("client_cert") or None,
        "client_key": cfg.get("client_key") or None,
        "client_key_password": cfg.get("client_key_password") or None,
        "ca_bundle": cfg.get("ca_bundle") or None,
        "verify": cfg.get("verify", True),
    }
    env_pw = os.environ.get(ENV_KEY_PASSWORD)
    if env_pw:
        resolved["client_key_password"] = env_pw
    return resolved


def _signature(tls: dict) -> tuple:
    return (
        tls["client_cert"],
        tls["client_key"],
        tls["client_key_password"],
        tls["ca_bundle"],
        bool(tls["verify"]),
    )


def is_configured(mtls_cfg: dict | None) -> bool:
    """True when the block asks for anything beyond default server verification."""
    tls = _resolve(mtls_cfg)
    return bool(tls["client_cert"]) or bool(tls["ca_bundle"]) or tls["verify"] is False


def build_verify(mtls_cfg: dict | None) -> VerifyValue:
    """Build an httpx ``verify=`` value from a ``security.mtls`` config block.

    Returns ``True`` (httpx default certifi verification) when nothing is
    customised, an ``ssl.SSLContext`` when a client certificate, private CA, or
    ``verify: false`` is configured. Raises if a configured certificate/CA file
    cannot be loaded — that is a deployment error and should fail loudly at
    startup / pod spawn rather than silently fall back to anonymous TLS.
    """
    tls = _resolve(mtls_cfg)
    if not tls["client_cert"] and not tls["ca_bundle"] and tls["verify"] is not False:
        return True  # nothing to customise — preserve prior behaviour exactly

    sig = _signature(tls)
    cached = _CONTEXT_CACHE.get(sig)
    if cached is not None:
        return cached

    if tls["verify"] is False:
        # Closed test networks only. Documented as unsafe; never the default.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        # A private ca_bundle replaces the public set (the common device-PKI
        # case); otherwise trust certifi, exactly as httpx does by default.
        ctx = ssl.create_default_context(cafile=tls["ca_bundle"] or certifi.where())

    if tls["client_cert"]:
        ctx.load_cert_chain(
            certfile=tls["client_cert"],
            keyfile=tls["client_key"],
            password=tls["client_key_password"],
        )

    _CONTEXT_CACHE[sig] = ctx
    return ctx


def reset_cache() -> None:
    """Drop cached contexts. For tests that swap cert files between cases."""
    _CONTEXT_CACHE.clear()
