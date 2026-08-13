# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Endpoint fingerprinting — pin what a device *is* (ADR-0015, F-69).

Three dimensions, deliberately never collapsed into one "verified" flag:

* **Authenticated** — the TLS **SPKI** digest. Cryptographic; proves this is the same
  endpoint as last time.
* **Declared** — MCP ``serverInfo`` / OpenAPI ``info``. Self-reported, therefore spoofable.
  Inventory that doubles as a change signal, never evidence of identity.
* **Behavioural** — ``canonical_tools_hash`` / ``tools_revision``, which already exist.

Why SPKI and not the certificate
--------------------------------
A routine renewal re-issues the certificate against the **same key**, so the SPKI is
unchanged and nothing fires. Pinning the certificate digest would alarm on every ACME
renewal — every 60-90 days, for every device — and
[ADR-0013 §8]'s argument applies unchanged: a control that fires constantly trains people
to approve reflexively, which destroys the signal exactly where it needs to mean something.
A *changed key* is indistinguishable from a substituted endpoint, and that is worth an alarm.

What this does not do
---------------------
The first observation is **trust on first use**: it establishes a baseline, it does not
validate anything. If the endpoint was already the wrong one at registration, the wrong
value is what gets pinned. Nothing here should be described as verifying identity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from loguru import logger

# Fingerprint states, mirrored on DeviceConfig.fingerprint_state.
STATE_UNPINNED = "unpinned"
STATE_PINNED = "pinned"
STATE_PENDING = "pending_approval"

# Verdicts from compare().
VERDICT_UNCHANGED = "unchanged"
VERDICT_FIRST_PIN = "first_pin"
VERDICT_CERT_ROTATED = "cert_rotated"  # same key, new cert — informational
VERDICT_DECLARED_CHANGED = "declared_changed"  # same key, new name/version — informational
VERDICT_KEY_CHANGED = "key_changed"  # SPKI moved — WARN, needs approval
VERDICT_KEY_AND_DECLARED_CHANGED = "key_and_declared_changed"  # strongest signal

# Verdicts that require a human decision before the device is trusted again.
NEEDS_APPROVAL = frozenset({VERDICT_KEY_CHANGED, VERDICT_KEY_AND_DECLARED_CHANGED})

POLICY_WARN = "warn"
POLICY_ENFORCE = "enforce"


@dataclass(frozen=True)
class Observation:
    """What a single probe saw. Every field optional — a plain-http upstream has no TLS
    dimension at all (ADR-0015 §7), and a probe that failed before the handshake has none
    of them."""

    tls_spki_sha256: str | None = None
    tls_cert_sha256: str | None = None
    tls_issuer: str | None = None
    tls_not_after: str | None = None
    declared_name: str | None = None
    declared_version: str | None = None

    def has_tls(self) -> bool:
        return bool(self.tls_spki_sha256)

    def is_empty(self) -> bool:
        """Nothing was learned. Distinct from "learned that nothing is there"."""
        return not any(
            (
                self.tls_spki_sha256,
                self.tls_cert_sha256,
                self.declared_name,
                self.declared_version,
            )
        )


def spki_sha256(der_cert: bytes) -> str:
    """SHA-256 of the certificate's SubjectPublicKeyInfo, hex encoded."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def observe_tls(ssl_object: Any) -> Observation:
    """Build an :class:`Observation` from a live TLS connection.

    ⚠️ ``getpeercert`` must be called **positionally**. The object handed back by
    httpcore's ``get_extra_info("ssl_object")`` is a raw ``_SSLSocket``, not the
    ``ssl.SSLSocket`` wrapper, so the documented ``binary_form=True`` keyword raises
    ``TypeError: _SSLSocket.getpeercert() takes no keyword arguments``.

    Never raises: a fingerprint that cannot be read must not break the request it rode in
    on. A failure here yields an empty observation, which compare() treats as "learned
    nothing" rather than as "the endpoint changed".
    """
    try:
        der = ssl_object.getpeercert(True)
        if not der:
            return Observation()
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        return Observation(
            tls_spki_sha256=spki_sha256(der),
            tls_cert_sha256=hashlib.sha256(der).hexdigest(),
            tls_issuer=cert.issuer.rfc4514_string(),
            tls_not_after=cert.not_valid_after_utc.isoformat(),
        )
    except Exception as exc:  # noqa: BLE001 — see docstring: must never break the request
        logger.debug(f"TLS fingerprint capture failed: {type(exc).__name__}: {exc}")
        return Observation()


def compare(stored: Observation, seen: Observation) -> str:
    """Classify ``seen`` against the pinned ``stored`` values.

    Returns one of the ``VERDICT_*`` constants. The classification exists so the common,
    boring cases do not drown the one that matters (ADR-0015 §3) — a single
    undifferentiated "fingerprint changed" alarm would fire mostly on certificate renewals
    and version bumps.

    Note the tool-surface hash is deliberately **not** an input: it changes on ordinary
    firmware and feature upgrades, and ``tools_revision`` already tracks it.
    """
    if seen.is_empty():
        # Learned nothing this round — an unreachable device, or a probe that failed before
        # the handshake. Absence of evidence is not evidence of change.
        return VERDICT_UNCHANGED

    if not stored.tls_spki_sha256 and not stored.declared_name:
        return VERDICT_FIRST_PIN

    declared_changed = _declared_changed(stored, seen)

    # Only compare the key when both sides have one. An https device that becomes
    # unreachable, or a probe that could not read the cert, must not read as "key removed".
    if stored.tls_spki_sha256 and seen.tls_spki_sha256:
        if stored.tls_spki_sha256 != seen.tls_spki_sha256:
            return VERDICT_KEY_AND_DECLARED_CHANGED if declared_changed else VERDICT_KEY_CHANGED
        if stored.tls_cert_sha256 and seen.tls_cert_sha256 and stored.tls_cert_sha256 != seen.tls_cert_sha256:
            # Same key, new certificate: the renewal case that must NOT alarm.
            return VERDICT_CERT_ROTATED

    return VERDICT_DECLARED_CHANGED if declared_changed else VERDICT_UNCHANGED


def _declared_changed(stored: Observation, seen: Observation) -> bool:
    """True only when the upstream reported something *different*, not when it reported
    nothing. A probe that skipped the handshake has no declared fields, and treating that
    as a change would alarm on every transient failure."""
    for old, new in (
        (stored.declared_name, seen.declared_name),
        (stored.declared_version, seen.declared_version),
    ):
        if new and old and new != old:
            return True
    return False


def resolve_policy(device_policy: str | None, default_policy: str | None) -> str:
    """Effective policy for a device: its own override, else the deployment default,
    else ``warn`` (ADR-0015 §5).

    Defaults to warn rather than enforce on purpose. A fleet that stops on certificate
    rotation is a fleet whose operators switch the check off within a quarter, and a
    disabled control detects nothing — strictly worse than a warning someone might read.
    """
    for candidate in (device_policy, default_policy):
        if candidate and candidate.lower() in (POLICY_WARN, POLICY_ENFORCE):
            return candidate.lower()
    return POLICY_WARN


def is_quarantined(fingerprint_state: str, effective_policy: str) -> bool:
    """Whether the device's *use* paths must refuse (ADR-0015 §9).

    Quarantine covers tool calls **and** resource reads: both send the device's credentials
    and return its data, differing only in code path, so stopping one and not the other
    would leave a quiet route to exactly what the quarantine prevents. Observation paths —
    reachability probes, diagnostics, GET /v1/devices — deliberately keep working, so a
    quarantined device stays distinguishable from a dead one.
    """
    return fingerprint_state == STATE_PENDING and effective_policy == POLICY_ENFORCE
