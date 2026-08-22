# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0023 — a break-glass entry is individually attributable, or the gateway refuses to start.

Two rules, both fatal and both without an override:

1. **`name` is mandatory.** Without it `build_static_authenticator` falls back to the *role*,
   so two people holding two different credentials would both audit as `key:admin` — the
   shared-anonymous-credential problem this ADR closes, reappearing through an omitted field.
2. **The key is a `secret://` reference, never a literal**, or the config document still
   carries the credential regardless of how it was generated.

The refusals are the point. Each test below asserts the gateway *does not start*, because a
break-glass path that is quietly misconfigured is discovered during the incident it exists for.
"""

from __future__ import annotations

import os
import stat

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from device_mcp_gateway.rbac import (
    BreakGlassConfigError,
    build_static_authenticator,
    scopes_for_role,
)

REF = "secret://t-3f9a1c2b7d4e8065/break-glass/alice#key"
SECRET = "0f8c2a1b" * 8
CI_KEY = "ci-key-literal-long-enough-to-not-warn"


def _bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.fixture()
def store(tmp_path):
    """A mounted-files store holding one break-glass credential, mode 0600."""
    path = tmp_path / "t-3f9a1c2b7d4e8065" / "break-glass" / "alice"
    path.mkdir(parents=True)
    key = path / "key"
    key.write_text(SECRET)
    key.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return tmp_path


def _cfg(store_root=None, **entry):
    gateway: dict = {"rbac": [entry]}
    if store_root is not None:
        gateway["credentials"] = {"root": str(store_root)}
    return {"gateway": gateway}


def test_flagged_entry_without_a_name_refuses_to_start(store):
    with pytest.raises(BreakGlassConfigError, match="no name"):
        build_static_authenticator(_cfg(store, break_glass=True, key=REF, role="admin"))


def test_a_blank_name_is_not_a_name(store):
    """`name: "   "` is an omitted field wearing a value."""
    with pytest.raises(BreakGlassConfigError, match="no name"):
        build_static_authenticator(_cfg(store, break_glass=True, name="   ", key=REF, role="admin"))


def test_a_literal_key_is_refused(store):
    with pytest.raises(BreakGlassConfigError, match="literal value"):
        build_static_authenticator(_cfg(store, break_glass=True, name="alice", key=SECRET, role="admin"))


def test_a_flagged_entry_with_no_key_is_refused(store):
    with pytest.raises(BreakGlassConfigError, match="no key"):
        build_static_authenticator(_cfg(store, break_glass=True, name="alice", role="admin"))


def test_no_resolver_configured_is_refused():
    """A secret:// reference with nowhere to resolve it is a broken break-glass path."""
    with pytest.raises(BreakGlassConfigError, match="no credential resolver"):
        build_static_authenticator(_cfg(None, break_glass=True, name="alice", key=REF, role="admin"))


def test_an_unresolvable_reference_is_refused(store):
    missing = "secret://t-3f9a1c2b7d4e8065/break-glass/bob#key"
    with pytest.raises(BreakGlassConfigError, match="could not be resolved"):
        build_static_authenticator(_cfg(store, break_glass=True, name="bob", key=missing, role="admin"))


def test_a_world_readable_secret_is_refused(store):
    """The resolver's ownership check is reused, not reimplemented — so it applies here too."""
    (store / "t-3f9a1c2b7d4e8065" / "break-glass" / "alice" / "key").chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    with pytest.raises(BreakGlassConfigError, match="could not be resolved"):
        build_static_authenticator(_cfg(store, break_glass=True, name="alice", key=REF, role="admin"))


def test_a_valid_flagged_entry_authenticates_as_the_named_person(store):
    auth = build_static_authenticator(_cfg(store, break_glass=True, name="alice", key=REF, role="admin"))
    principal = auth.authenticate(_bearer(SECRET))
    assert principal is not None
    assert principal.subject == "key:alice", "the audit must name the person, never the role"
    assert principal.break_glass is True
    assert principal.auth_method == "break_glass"
    assert principal.scopes == scopes_for_role("admin"), "ADR-0023 property 4: scope unchanged"


def test_an_ordinary_entry_is_untouched_by_any_of_this():
    """`gateway.rbac` still serves CI keys and machine credentials as it always did."""
    auth = build_static_authenticator(_cfg(None, name="ci", key=CI_KEY, role="viewer"))
    principal = auth.authenticate(_bearer(CI_KEY))
    assert principal is not None
    assert principal.subject == "key:ci"
    assert principal.break_glass is False
    assert principal.auth_method == "api_key"


def test_an_unnamed_ORDINARY_entry_still_falls_back_to_its_role(store):
    """The mandatory-name rule is scoped to flagged entries, deliberately.

    Making it universal would break existing configs for no security gain: an unflagged
    machine key auditing as `key:viewer` is imprecise, not anonymous-by-design.
    """
    auth = build_static_authenticator(_cfg(None, key=CI_KEY, role="viewer"))
    assert auth.authenticate(_bearer(CI_KEY)).subject == "key:viewer"


def test_refusal_has_no_override(store):
    """Unlike the weak-key gate, there is no allow_... escape for a malformed flagged entry."""
    cfg = _cfg(store, break_glass=True, key=REF, role="admin")
    cfg["gateway"]["allow_weak_keys"] = True
    cfg["gateway"]["allow_anonymous"] = True
    with pytest.raises(BreakGlassConfigError):
        build_static_authenticator(cfg)


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses mode checks")
def test_the_resolved_key_never_appears_in_the_config_document(store):
    """The whole point of the reference: the document carries a pointer, not the credential."""
    cfg = _cfg(store, break_glass=True, name="alice", key=REF, role="admin")
    build_static_authenticator(cfg)
    assert SECRET not in repr(cfg), "resolution must not write the material back into config"
