# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Which credential material the gateway mints itself, and therefore never exports.

ADR-0018 §1a draws one line through the credential space: **operator-provisioned versus
gateway-minted.** A tenant writes an API key, a `client_secret`, a `password`; the gateway
reads them and nothing else ever changes them. A rotated OAuth2 refresh token is the
opposite — the provider hands one back mid-exchange and the gateway is the only party
present, so the gateway must write it. That asymmetry is why §1's by-reference model covers
the first group and cannot cover the second.

§3 takes the consequence for backup: **a gateway-minted rotating token is excluded from
every archive, unconditionally.** Not encrypted more carefully — excluded.

Why exclusion rather than a conditional
---------------------------------------
An earlier draft kept the whole ``backup:*`` apparatus alive for any stack that happened to
own a rotating-token device. That leaves passphrase, KDF, envelope and canary as a path
that fires for almost nobody, and this project has direct evidence about what that costs: a
1321-test suite passed while the feature under it did not work on a live cluster. Protection
code that almost never executes is the exact shape that rots quietly and fails the one time
an incident depends on it.

And the guarantee it protects frequently does not hold anyway. Many providers invalidate the
previous refresh token the moment a new one is issued, so a token archived last week can
already be dead server-side before anyone restores it — for reasons no archive design
controls.

The deciding argument is that this is **the category the archive already excludes.**
``backup/export.py`` omits claims, leases, worker membership, streams, sessions, idempotency
markers and rate-limit counters, on the stated rule that the archive carries *registration
inputs, not runtime state*. A refresh token is gateway-accumulated runtime state that was
slipping through only because it is stored inside ``auth_config`` next to genuine inputs.
This applies the existing rule rather than adding an exception to it.

What is NOT excluded
--------------------
Everything that makes the device a device: its registration, its ``credential_ref``, and the
operator-provisioned ``client_secret`` / ``password`` a reference points at. Nothing about
the device's identity or its ability to be re-established is lost — which is what bounds the
cost to the one grant that cannot re-mint itself.
"""

from __future__ import annotations

from typing import Any

#: The credential fields the gateway mints and rotates itself, per auth handler type. A
#: handler absent from this map has nothing gateway-minted in it and is exported whole.
#:
#: Keyed by ``auth_type`` — the same discriminator ``worker.runner._auth_from_config`` uses
#: to pick a handler class — so a new handler that mints its own material is added here in
#: one place rather than by teaching export and restore about it separately.
ROTATING_FIELDS: dict[str, tuple[str, ...]] = {
    "oauth2": ("refresh_token",),
}

#: The grants whose credential IS the rotating token, so excluding it leaves nothing that
#: can re-mint one. ``client_credentials`` and ``password`` both survive an archive intact:
#: their operator-provisioned inputs are still there and the gateway simply re-runs the
#: token exchange on first use.
#:
#: ``authorization_code`` is the other place consent shows up and is **out of scope for this
#: gateway** — ``auth/oauth2.py`` restricts ``grant_type`` to the three non-interactive
#: grants and raises on anything else. Were a consent-requiring grant added later, this is
#: the set it would join.
CONSENT_BOUND_GRANTS = frozenset({"refresh_token"})


def strip_rotating(auth_type: str | None, payload: dict[str, Any]) -> list[str]:
    """Remove gateway-minted material from a credential payload **in place**.

    Returns the field names actually removed, so the archive can record what it dropped
    rather than leaving a reader to infer it from an absence. An absence is ambiguous: a
    record with no ``refresh_token`` may be one this rule stripped, or a
    ``client_credentials`` device that never had one, and those two call for entirely
    different advice on restore.

    Mutates rather than copying because the caller owns a payload it just parsed out of
    storage for this one purpose; returning a second dict would leave two objects around,
    one of which still holds the token.
    """
    removed: list[str] = []
    for field in ROTATING_FIELDS.get(auth_type or "", ()):
        if payload.pop(field, None) is not None:
            removed.append(field)
    return removed


def needs_reconnect(auth_type: str | None, payload: dict[str, Any]) -> bool:
    """Would this device arrive from a restore unable to authenticate?

    True only where the excluded token *was* the credential. The check is on the grant
    rather than on "did we strip something", because a ``client_credentials`` device can
    also carry a rotated ``refresh_token`` — providers hand them back — and stripping it
    costs that device nothing at all. Reporting it as needing a human would be a false alarm
    on a device that restores seamlessly, and ADR-0015 §2's argument applies here too: a
    control that fires on healthy devices is one operators learn to dismiss.
    """
    if (auth_type or "") != "oauth2":
        return False
    return (payload.get("grant_type") or "client_credentials") in CONSENT_BOUND_GRANTS
