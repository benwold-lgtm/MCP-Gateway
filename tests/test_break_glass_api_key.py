# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0023 slice 4 — `gateway.api_key` is break-glass, but only where it actually is one.

The rule is **conditional on deployment shape, not on which config field the key sits in**,
and both halves are load-bearing:

- **OIDC configured** — the static key is reached only when the JWT path fails or is absent.
  That is break-glass in substance, so it gets the loud treatment; leaving it unflagged would
  be a second, unhardened emergency path running beside the named entries.
- **No OIDC at all** — there is nothing to fall back *from*. The key is the deployment's
  ordinary, continuous, everyday credential, and flagging it would fire a high-severity event
  and an activation on entirely normal traffic. The ADR calls treating this case as
  break-glass "wrong, not merely unnecessary", and
  `test_without_oidc_nothing_changes_at_all` is what keeps it that way.

**What flagging an unnamed key does not buy, stated here because it is easy to assume it
does:** these keys have no configured name, so the audit can record *that* break-glass was
used and not *by whom*, and they carry no `issued` date so no expiry applies. Flagging makes
them loud; only a named `gateway.rbac` entry makes them attributable. The events say so
(`attributable: false`), and so does the startup warning.
"""

from __future__ import annotations

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from loguru import logger

from device_mcp_gateway.rbac import build_static_authenticator, scopes_for_role

API_KEY = "gw-api-key-long-enough-to-not-warn"
ADMIN_KEY = "gw-admin-key-long-enough-to-not-warn"
VIEWER_KEY = "gw-viewer-key-long-enough-to-not-warn"


def _bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _cfg(*, oidc: bool, api_key=API_KEY, rbac=None):
    gateway: dict = {"api_key": api_key}
    if rbac is not None:
        gateway["rbac"] = rbac
    if oidc:
        gateway["oidc"] = {
            "enabled": True,
            "issuer": "https://idp.example.com/realms/tenant",
            "audience": "mcp-gateway",
            "group_roles": {"mcp-admins": "admin"},
        }
    return {"gateway": gateway}


@pytest.fixture
def captured_logs():
    """Loguru output at WARNING and above — `caplog` does not see it."""
    records: list[str] = []
    sink_id = logger.add(lambda m: records.append(str(m)), level="WARNING")
    try:
        yield records
    finally:
        logger.remove(sink_id)


# ── OIDC configured: the key IS the emergency path ───────────────────────────────────────


def test_with_oidc_the_api_key_becomes_break_glass():
    auth = build_static_authenticator(_cfg(oidc=True))
    principal = auth.authenticate(_bearer(API_KEY))

    assert principal.break_glass is True
    assert principal.auth_method == "break_glass"
    assert principal.scopes == scopes_for_role("admin"), "property 4: scope is unchanged"


def test_with_oidc_the_admin_env_key_becomes_break_glass(monkeypatch):
    """`MCP_ADMIN_KEY` is the mechanism ADR-0023 exists to replace, and with OIDC on it is a
    fallback for exactly the same reason `gateway.api_key` is."""
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    auth = build_static_authenticator(_cfg(oidc=True, api_key=None))

    assert auth.authenticate(_bearer(ADMIN_KEY)).break_glass is True


def test_the_viewer_key_is_never_break_glass(monkeypatch):
    """Break-glass exists to *repair* a deployment whose identity path is down. A read-only
    credential cannot repair anything, so flagging it would be loudness with no incident
    behind it."""
    monkeypatch.setenv("MCP_VIEWER_KEY", VIEWER_KEY)
    auth = build_static_authenticator(_cfg(oidc=True, api_key=None))

    principal = auth.authenticate(_bearer(VIEWER_KEY))
    assert principal.break_glass is False
    assert principal.auth_method == "api_key"


def test_the_flagged_env_key_is_marked_unattributable():
    """The honest limit of slice 4. `key:legacy` looks enough like an identity to be mistaken
    for one, so the fact that it names nobody has to travel with the principal."""
    auth = build_static_authenticator(_cfg(oidc=True))
    principal = auth.authenticate(_bearer(API_KEY))

    assert principal.break_glass is True
    assert principal.attributable is False


def test_a_named_entry_stays_attributable(tmp_path):
    """The contrast that makes the flag worth acting on: a named entry names a person."""
    import stat

    d = tmp_path / "t-abc" / "break-glass" / "alice"
    d.mkdir(parents=True)
    (d / "key").write_text("k" * 48)
    (d / "key").chmod(stat.S_IRUSR | stat.S_IWUSR)

    import datetime as dt

    cfg = _cfg(
        oidc=True,
        api_key=None,
        rbac=[
            {
                "name": "alice",
                "break_glass": True,
                "key": "secret://t-abc/break-glass/alice#key",
                "role": "admin",
                "issued": dt.date.today().isoformat(),
            }
        ],
    )
    cfg["gateway"]["credentials"] = {"root": str(tmp_path)}
    auth = build_static_authenticator(cfg)

    principal = auth.authenticate(_bearer("k" * 48))
    assert principal.subject == "key:alice"
    assert (principal.break_glass, principal.attributable) == (True, True)


# ── No OIDC: deliberately untouched ──────────────────────────────────────────────────────


def test_without_oidc_nothing_changes_at_all(captured_logs):
    """The half the ADR is most explicit about.

    With no OIDC the plain `Authenticator` is the only one built and this key is the
    deployment's everyday credential — not a rare emergency path. Flagging it would fire a
    high-severity event and an activation on ordinary traffic, which is why the ADR calls it
    "wrong, not merely unnecessary" rather than harmless extra caution.
    """
    auth = build_static_authenticator(_cfg(oidc=False))
    principal = auth.authenticate(_bearer(API_KEY))

    assert principal.break_glass is False
    assert principal.auth_method == "api_key"
    assert not any("BREAK-GLASS" in line for line in captured_logs)
    # `attributable` stays False here, and that is not a slice-4 side effect: `key:legacy` is
    # a fixed placeholder rather than a configured name whether or not the key is flagged.
    # The field deliberately does not change meaning with `break_glass` — a value only valid
    # under a condition is one a later call site reads without checking the condition.
    assert principal.attributable is False


def test_oidc_present_but_disabled_is_the_same_as_absent():
    """`enabled: false` with a fully-populated issuer block is a deployment that has staged
    OIDC and not turned it on. Nothing is falling back, so nothing is break-glass."""
    cfg = _cfg(oidc=True)
    cfg["gateway"]["oidc"]["enabled"] = False

    assert build_static_authenticator(cfg).authenticate(_bearer(API_KEY)).break_glass is False


def test_without_oidc_the_admin_key_is_still_an_ordinary_key(monkeypatch):
    monkeypatch.setenv("MCP_ADMIN_KEY", ADMIN_KEY)
    auth = build_static_authenticator(_cfg(oidc=False, api_key=None))
    assert auth.authenticate(_bearer(ADMIN_KEY)).break_glass is False


# ── The startup warning says what flagging does not buy ──────────────────────────────────


def test_the_warning_names_both_limits(captured_logs):
    """Attribution and expiry are exactly what an operator would assume they had just gained,
    and are exactly what an unnamed key does not provide."""
    build_static_authenticator(_cfg(oidc=True))
    warning = " ".join(captured_logs)

    assert "CANNOT say by whom" in warning
    assert "NO EXPIRY" in warning


def test_the_warning_calls_out_the_bff_password_path(captured_logs):
    """The carve-out that is not hypothetical: flagging this key before the console's password
    path has its own entry fires a high-severity event on every login."""
    build_static_authenticator(_cfg(oidc=True))
    assert "UI/BFF" in " ".join(captured_logs)


def test_the_warning_escalates_once_named_entries_exist(captured_logs, tmp_path):
    """Before any named entry the key is the documented bootstrap fallback. After one, it is a
    second unattributable path running beside a hardened one — a different situation, and the
    operator should be told which they are in."""
    import datetime as dt
    import stat

    d = tmp_path / "t-abc" / "break-glass" / "alice"
    d.mkdir(parents=True)
    (d / "key").write_text("k" * 48)
    (d / "key").chmod(stat.S_IRUSR | stat.S_IWUSR)

    build_static_authenticator(_cfg(oidc=True))
    assert "bootstrap window is over" not in " ".join(captured_logs)
    captured_logs.clear()

    cfg = _cfg(
        oidc=True,
        rbac=[
            {
                "name": "alice",
                "break_glass": True,
                "key": "secret://t-abc/break-glass/alice#key",
                "role": "admin",
                "issued": dt.date.today().isoformat(),
            }
        ],
    )
    cfg["gateway"]["credentials"] = {"root": str(tmp_path)}
    build_static_authenticator(cfg)

    assert "bootstrap window is over" in " ".join(captured_logs)


def test_no_warning_without_oidc(captured_logs):
    build_static_authenticator(_cfg(oidc=False))
    assert not any("BREAK-GLASS credential" in line for line in captured_logs)
