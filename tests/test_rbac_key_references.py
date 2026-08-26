# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""An ordinary `gateway.rbac` entry may hold its key by reference, and the `console` role.

Both are prerequisites for ADR-0023 slice 4, and neither is about break-glass.

**Why the reference.** `config.yaml` is mounted from a ConfigMap, and `gateway.rbac[].key` is
read as a literal out of that document — so giving the console's BFF its own named entry, the
thing slice 4 requires before `gateway.api_key` can be flagged, would put a live bearer
credential somewhere `kubectl get configmap` prints it. Slice 1 required a `secret://`
reference for *flagged* entries; this permits one everywhere.

**Why it is also a security fix.** Before this, `key: "secret://..."` on an unflagged entry
did not error and did not resolve — the reference *string* became the valid bearer token.
`test_a_reference_string_is_not_itself_a_valid_token` demonstrates that against the old
behaviour: anyone who could read the ConfigMap could authenticate with the pointer.

**Why the role.** Nothing in `ROLE_SCOPES` matched what a password session actually needs,
which is why the BFF holds an *admin* key and compensates in its own layer.
"""

from __future__ import annotations

import stat

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from device_mcp_gateway.rbac import (
    ALL_SCOPES,
    ROLE_SCOPES,
    SCOPE_BACKUP_EXPORT_PORTABLE,
    SCOPE_BACKUP_READ,
    SCOPE_BACKUP_WRITE,
    SCOPE_DEVICES_READ,
    SCOPE_DEVICES_WRITE,
    SCOPE_METRICS_READ,
    SCOPE_SUPPORT_ADMINISTER,
    SCOPE_TOOLS_CALL,
    RbacConfigError,
    build_static_authenticator,
    scopes_for_role,
)

REF = "secret://t-3f9a1c2b7d4e8065/console/bff#token"
SECRET = "7b1e4d2a" * 8
LITERAL = "ci-key-literal-long-enough-to-not-warn"


def _bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.fixture()
def store(tmp_path):
    """A mounted-files store holding the console's gateway token, mode 0600."""
    path = tmp_path / "t-3f9a1c2b7d4e8065" / "console" / "bff"
    path.mkdir(parents=True)
    token = path / "token"
    token.write_text(SECRET)
    token.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return tmp_path


def _cfg(store_root=None, **entry):
    gateway: dict = {"rbac": [entry]}
    if store_root is not None:
        gateway["credentials"] = {"root": str(store_root)}
    return {"gateway": gateway}


# ── The reference resolves ───────────────────────────────────────────────────────────────


def test_an_ordinary_entry_can_hold_its_key_by_reference(store):
    auth = build_static_authenticator(_cfg(store, name="bff-password-sessions", key=REF, role="console"))

    principal = auth.authenticate(_bearer(SECRET))
    assert principal is not None
    assert principal.subject == "key:bff-password-sessions"
    assert principal.break_glass is False, "a reference is not a break-glass flag"
    assert principal.auth_method == "api_key", "still an ordinary static key, just held elsewhere"


def test_a_reference_string_is_not_itself_a_valid_token(store):
    """The footgun this closes, stated as the property that must hold.

    Pre-change, an unflagged entry took its key as a literal whatever it looked like, so
    `key: "secret://..."` made the *pointer* the credential. The document is a ConfigMap:
    anyone who could read it could authenticate. The reference must never be accepted as the
    thing it points at.
    """
    auth = build_static_authenticator(_cfg(store, name="bff-password-sessions", key=REF, role="console"))

    with pytest.raises(Exception) as exc:
        auth.authenticate(_bearer(REF))
    assert getattr(exc.value, "status_code", None) == 401


def test_the_resolved_secret_never_appears_in_the_config_document(store):
    cfg = _cfg(store, name="bff-password-sessions", key=REF, role="console")
    build_static_authenticator(cfg)
    assert SECRET not in repr(cfg)


def test_a_literal_key_still_works_untouched():
    """The change permits a reference; it does not require one. Existing configs are configs
    that already work, and breaking them would buy nothing."""
    auth = build_static_authenticator(_cfg(None, name="ci", key=LITERAL, role="viewer"))
    assert auth.authenticate(_bearer(LITERAL)).subject == "key:ci"


def test_literal_and_reference_entries_coexist(store):
    cfg = {
        "gateway": {
            "credentials": {"root": str(store)},
            "rbac": [
                {"name": "ci", "key": LITERAL, "role": "viewer"},
                {"name": "bff-password-sessions", "key": REF, "role": "console"},
            ],
        }
    }
    auth = build_static_authenticator(cfg)
    assert auth.authenticate(_bearer(LITERAL)).subject == "key:ci"
    assert auth.authenticate(_bearer(SECRET)).subject == "key:bff-password-sessions"


# ── A broken reference is fatal, not silently dropped ────────────────────────────────────


def test_an_unresolvable_reference_refuses_to_start(store):
    """Dropping it instead would leave the console's BFF getting unexplained 401s, with the
    reason only in a log line nobody is reading yet."""
    missing = "secret://t-3f9a1c2b7d4e8065/console/absent#token"
    with pytest.raises(RbacConfigError, match="could not be resolved"):
        build_static_authenticator(_cfg(store, name="bff-password-sessions", key=missing, role="console"))


def test_a_reference_with_no_resolver_configured_refuses_to_start():
    with pytest.raises(RbacConfigError, match="no credential resolver"):
        build_static_authenticator(_cfg(None, name="bff-password-sessions", key=REF, role="console"))


def test_the_failure_is_not_reported_as_a_break_glass_one(store):
    """An unflagged entry is not break-glass, and an operator reading the message should not
    be sent looking for a flag that is not there."""
    from device_mcp_gateway.rbac import BreakGlassConfigError

    missing = "secret://t-3f9a1c2b7d4e8065/console/absent#token"
    with pytest.raises(RbacConfigError) as exc:
        build_static_authenticator(_cfg(store, name="bff-password-sessions", key=missing, role="console"))
    assert not isinstance(exc.value, BreakGlassConfigError)
    assert "break_glass" not in str(exc.value)


@pytest.mark.skipif(__import__("os").geteuid() == 0, reason="root bypasses mode checks")
def test_a_world_readable_secret_is_refused(store):
    """The resolver's ownership check is reused, not reimplemented — so an ordinary entry
    gets it too, not just a flagged one."""
    (store / "t-3f9a1c2b7d4e8065" / "console" / "bff" / "token").chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    with pytest.raises(RbacConfigError, match="could not be resolved"):
        build_static_authenticator(_cfg(store, name="bff-password-sessions", key=REF, role="console"))


# ── The console role ─────────────────────────────────────────────────────────────────────


def test_console_is_exactly_what_a_password_session_reaches():
    """Mapped from the BFF's relayed routes, not guessed: device CRUD and diagnostics
    (`devices:read`/`devices:write`), `/metrics/summary` (`metrics:read`), the MCP
    invocation path (`tools:call`), and administering support access (`support:administer`,
    ADR-0017 — the same BFF process mediates both the provider-plane raise and the
    tenant-plane decide/list/revoke today, pre-ADR-0021)."""
    assert scopes_for_role("console") == frozenset(
        {SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, SCOPE_METRICS_READ, SCOPE_TOOLS_CALL, SCOPE_SUPPORT_ADMINISTER}
    )


def test_console_carries_no_backup_scope_at_all():
    """The reason the role exists.

    The BFF refuses password sessions on all four backup/restore routes because the admin
    token it proxies with holds every `backup:*` scope — "admitting one here is a complete
    credential dump", in its own comment. That guarantee currently holds only as long as no
    BFF route forgets the guard. A role that cannot express the scope moves it to the
    gateway, where a console-side bug cannot undo it.
    """
    console = scopes_for_role("console")
    for scope in (SCOPE_BACKUP_READ, SCOPE_BACKUP_WRITE, SCOPE_BACKUP_EXPORT_PORTABLE):
        assert scope not in console
    assert console < ALL_SCOPES, "strictly less than admin"


def test_console_is_the_union_of_operator_and_caller():
    """Written as a union in the source so it cannot drift: if `operator` gains a scope, the
    console gains it too, which a hand-copied list would silently stop doing."""
    assert scopes_for_role("console") == ROLE_SCOPES["operator"] | ROLE_SCOPES["caller"]


def test_console_adds_the_one_thing_operator_lacked():
    """Why no existing role fitted: `operator` cannot invoke tools and `caller` cannot manage
    the fleet, so the console had to be given `admin` — and with it, backup."""
    assert SCOPE_TOOLS_CALL not in ROLE_SCOPES["operator"]
    assert SCOPE_DEVICES_WRITE not in ROLE_SCOPES["caller"]
    assert SCOPE_TOOLS_CALL in scopes_for_role("console")
    assert SCOPE_DEVICES_WRITE in scopes_for_role("console")


def test_an_entry_can_be_given_the_console_role(store):
    auth = build_static_authenticator(_cfg(store, name="bff-password-sessions", key=REF, role="console"))
    assert auth.authenticate(_bearer(SECRET)).scopes == scopes_for_role("console")
