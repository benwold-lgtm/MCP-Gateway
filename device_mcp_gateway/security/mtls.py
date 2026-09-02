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

``verify`` can also be set via ``MCP_MTLS_VERIFY`` (env wins over the fleet
config), so a compose deployment talking to self-signed devices (UniFi
consoles, Home Assistant, ...) doesn't need a mounted config-file override just
for this one flag — mirrors ``MCP_ALLOW_PRIVATE_TARGETS``. Same caveat applies:
disable verification only on a trusted closed network.

Per-device trust
----------------
A ``devices`` sub-block overrides any of the five keys above **for one device**,
inheriting the rest from the fleet block::

    security:
      mtls:
        ca_bundle: /etc/mcp/tls/device-ca.pem   # fleet default
        devices:
          unifi.lab.internal:
            verify: false                       # this device only; the fleet still verifies
          switch-a.internal:
            ca_bundle:   /etc/mcp/tls/vendor-a-ca.pem
            client_cert: /etc/mcp/tls/vendor-a-client.crt
            client_key:  /etc/mcp/tls/vendor-a-client.key

This exists because trust was previously **fleet-global**: one self-signed device
forced its CA — or worse, ``verify: false`` — onto every other outbound call the
process made. A per-device override widens trust for that device and nothing else.

Precedence, most specific first: ``devices.<hostname>.<key>`` → the env override
→ the fleet ``security.mtls.<key>``. A per-device block deliberately beats the env
var: ``MCP_MTLS_VERIFY=false`` is a fleet-level switch, and a device that names
``verify: true`` is the more specific statement. The env *password* is the
exception — it unlocks the fleet client key, so it is applied only when the device
inherits the fleet key rather than naming its own (see ``_resolve``).

Design notes:
  * We return an ``ssl.SSLContext`` (not the deprecated ``cert=`` / string
    ``verify=`` httpx kwargs) so the call sites stay forward-compatible with
    httpx >= 0.28, where passing an SSLContext to ``verify=`` is the supported
    path.
  * **Trust decisions stay in OpenSSL via the stdlib** — ``ssl.create_default_context``
    builds the chain and checks name constraints. Per-device trust is one
    ``SSLContext`` per distinct profile, deliberately *not* ``cryptography``'s
    ``x509.verification`` API, which would make PYSEC-2026-3553/3554 reachable on
    exactly this path. See docs/testing-gaps.md#tg-4 for the full constraint.
  * When nothing is configured we return ``True`` — httpx's default certifi-based
    server verification — so non-mTLS deployments behave exactly as before.
  * The default trust anchor is certifi (what httpx itself uses), not the OS
    store, so behaviour is identical across hosts unless a ``ca_bundle`` is given.
  * Built contexts are cached by their *resolved* signature, so devices that
    resolve to the same profile share one context and the cache stays bounded by
    the number of distinct profiles in the config — not by the device count.
"""

from __future__ import annotations

import os
import ssl
from typing import Union

import certifi

ENV_KEY_PASSWORD = "MCP_TLS_CLIENT_KEY_PASSWORD"  # nosec B105 — env-var name, not a secret
ENV_VERIFY = "MCP_MTLS_VERIFY"

# The sub-block holding per-device overrides, and the keys one may contain. Anything
# else in a device block is a hard error rather than a warning: a misspelt `ca_bundle`
# would silently leave that device on the fleet trust set, which is a security
# downgrade that looks exactly like success.
DEVICES_KEY = "devices"
PROFILE_KEYS = frozenset({"client_cert", "client_key", "client_key_password", "ca_bundle", "verify"})

VerifyValue = Union[ssl.SSLContext, bool]

# Signature -> built verify value. Building an SSLContext loads cert files from
# disk, so cache by the resolved inputs; devices resolving to the same profile
# (the common case — most or all inherit the fleet block) share one context.
_CONTEXT_CACHE: dict[tuple, VerifyValue] = {}


def _device_block(mtls_cfg: dict | None, hostname: str | None) -> dict:
    """The ``devices.<hostname>`` override block, or ``{}`` when there is none."""
    if not hostname:
        return {}
    devices = (mtls_cfg or {}).get(DEVICES_KEY) or {}
    if not isinstance(devices, dict):
        return {}
    block = devices.get(hostname)
    return block if isinstance(block, dict) else {}


def _resolve(mtls_cfg: dict | None, hostname: str | None = None) -> dict:
    """Flatten a ``security.mtls`` block for one device (or the fleet default).

    Layered most-specific-last: fleet config, then the env overrides, then the
    ``devices.<hostname>`` block. Passing ``hostname=None`` yields the fleet
    profile, which is what every caller got before per-device trust existed.
    """
    cfg = mtls_cfg or {}
    overlay = _device_block(cfg, hostname)
    resolved = {
        "client_cert": cfg.get("client_cert") or None,
        "client_key": cfg.get("client_key") or None,
        "client_key_password": cfg.get("client_key_password") or None,
        "ca_bundle": cfg.get("ca_bundle") or None,
        "verify": cfg.get("verify", True),
    }

    # MCP_MTLS_VERIFY overrides security.mtls.verify (mirrors MCP_ALLOW_PRIVATE_TARGETS):
    # a compose deployment shouldn't need a config-file mount just to talk to a
    # self-signed device on a trusted closed network. A per-device `verify` is applied
    # after this, so naming one device explicitly still beats the fleet-wide switch.
    env_verify = os.environ.get(ENV_VERIFY, "").strip()
    if env_verify:
        resolved["verify"] = env_verify.lower() not in ("0", "false", "no")

    # A password belongs to the key it unlocks. When a device brings its own client
    # cert/key, neither the fleet config password nor MCP_TLS_CLIENT_KEY_PASSWORD
    # applies to it — those unlock the *fleet* key. The device block must name its own
    # (it is applied by the overlay loop below). Handing a vendor's key someone else's
    # password either fails confusingly, or silently "works" because both happen to be
    # unencrypted, hiding the misconfiguration until the day one of them isn't.
    device_brings_own_key = bool(overlay.get("client_cert") or overlay.get("client_key"))
    if device_brings_own_key:
        resolved["client_key_password"] = None
    else:
        env_pw = os.environ.get(ENV_KEY_PASSWORD)
        if env_pw:
            resolved["client_key_password"] = env_pw

    for key in PROFILE_KEYS:
        if key in overlay:
            value = overlay[key]
            resolved[key] = value if key == "verify" else (value or None)
    return resolved


def _signature(tls: dict) -> tuple:
    return (
        tls["client_cert"],
        tls["client_key"],
        tls["client_key_password"],
        tls["ca_bundle"],
        bool(tls["verify"]),
    )


def is_configured(mtls_cfg: dict | None, hostname: str | None = None) -> bool:
    """True when the resolved profile asks for anything beyond default server verification."""
    tls = _resolve(mtls_cfg, hostname)
    return bool(tls["client_cert"]) or bool(tls["ca_bundle"]) or tls["verify"] is False


def build_verify(mtls_cfg: dict | None, hostname: str | None = None) -> VerifyValue:
    """Build an httpx ``verify=`` value from a ``security.mtls`` config block.

    With ``hostname``, resolves that device's profile (its ``devices.<hostname>``
    overrides layered over the fleet block); without one, the fleet profile.

    Returns ``True`` (httpx default certifi verification) when nothing is
    customised, an ``ssl.SSLContext`` when a client certificate, private CA, or
    ``verify: false`` is configured. Raises if a configured certificate/CA file
    cannot be loaded — that is a deployment error and should fail loudly at
    startup / pod spawn rather than silently fall back to anonymous TLS.
    """
    tls = _resolve(mtls_cfg, hostname)
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


def device_profiles(mtls_cfg: dict | None) -> list[str]:
    """Hostnames that carry a ``devices.<hostname>`` override block."""
    devices = (mtls_cfg or {}).get(DEVICES_KEY) or {}
    return sorted(devices) if isinstance(devices, dict) else []


def preflight(mtls_cfg: dict | None) -> list[str]:
    """Validate and eagerly build every declared TLS profile. Raises on a bad one.

    Called once at gateway/worker startup. Without it, a per-device profile is only
    built the first time that device is touched, so an unreadable CA file or a
    misspelt key surfaces hours later as one device mysteriously failing — the fleet
    profile has always failed at startup, and per-device trust must not be quieter
    than the thing it replaces.

    Returns the hostnames that were validated (for logging/tests).
    """
    devices = (mtls_cfg or {}).get(DEVICES_KEY)
    if devices is not None and not isinstance(devices, dict):
        raise ValueError(f"security.mtls.{DEVICES_KEY} must be a mapping of hostname -> TLS overrides")

    for hostname in device_profiles(mtls_cfg):
        block = _device_block(mtls_cfg, hostname)
        unknown = sorted(set(block) - PROFILE_KEYS)
        if unknown:
            raise ValueError(
                f"security.mtls.{DEVICES_KEY}.{hostname}: unknown key(s) {', '.join(unknown)} — "
                f"valid keys are {', '.join(sorted(PROFILE_KEYS))}. Refusing to start: an ignored key "
                f"here means this device silently falls back to the fleet trust set."
            )

    # Build the fleet profile first so its failure is still reported as the fleet's.
    build_verify(mtls_cfg)
    validated = []
    for hostname in device_profiles(mtls_cfg):
        try:
            build_verify(mtls_cfg, hostname)
        except (OSError, ssl.SSLError) as exc:
            raise ValueError(f"security.mtls.{DEVICES_KEY}.{hostname}: cannot build TLS context — {exc}") from exc
        validated.append(hostname)
    return validated


def describe(mtls_cfg: dict | None, hostname: str | None = None) -> dict:
    """Summarise the resolved TLS profile for diagnostics (no secrets, no full paths).

    File paths are operator-supplied config, but ``/devices/{h}/diagnostics`` is a
    ``devices:read`` surface — a narrower scope than the one that writes the config.
    Report basenames so an operator can tell *which* CA a device resolved to without
    the endpoint disclosing the filesystem layout.
    """
    tls = _resolve(mtls_cfg, hostname)
    return {
        "source": "device" if _device_block(mtls_cfg, hostname) else "fleet",
        "verify": bool(tls["verify"]),
        "ca_bundle": os.path.basename(tls["ca_bundle"]) if tls["ca_bundle"] else None,
        "client_cert": bool(tls["client_cert"]),
    }


class TlsProfiles:
    """Per-device TLS resolution, bound to one ``security.mtls`` block.

    Components that make outbound device calls hold one of these instead of a single
    pre-built ``verify=`` value, so the trust decision is made *per device* at the
    point of use. Built contexts are shared via the module cache, so resolving the
    same profile for a hundred devices costs one context and one file read.

    ``key_for`` exists for callers that pool something per profile — the spec fetcher
    and health checker keep one ``httpx.AsyncClient`` per distinct profile, because a
    single shared client would put every device back on one TLS config, which is the
    exact limitation this class removes.
    """

    __slots__ = ("_cfg",)

    def __init__(self, mtls_cfg: dict | None) -> None:
        self._cfg = mtls_cfg or {}

    @classmethod
    def from_config(cls, config: dict | None) -> "TlsProfiles":
        """Build from a whole gateway/worker config (reads ``security.mtls``)."""
        return cls((config or {}).get("security", {}).get("mtls"))

    def for_device(self, hostname: str | None) -> VerifyValue:
        return build_verify(self._cfg, hostname)

    def fleet(self) -> VerifyValue:
        """The profile for calls that aren't attributable to one device."""
        return build_verify(self._cfg)

    def key_for(self, hostname: str | None) -> tuple:
        return _signature(_resolve(self._cfg, hostname))

    def describe(self, hostname: str | None) -> dict:
        return describe(self._cfg, hostname)

    def preflight(self) -> list[str]:
        return preflight(self._cfg)

    @property
    def overridden_hostnames(self) -> list[str]:
        return device_profiles(self._cfg)


def reset_cache() -> None:
    """Drop cached contexts. For tests that swap cert files between cases."""
    _CONTEXT_CACHE.clear()
