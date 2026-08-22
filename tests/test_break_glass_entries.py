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

import datetime as dt
import os
import stat

import pytest
from fastapi import HTTPException
from loguru import logger
from fastapi.security import HTTPAuthorizationCredentials

from device_mcp_gateway.rbac import (
    BreakGlassConfigError,
    build_static_authenticator,
    scopes_for_role,
)

REF = "secret://t-3f9a1c2b7d4e8065/break-glass/alice#key"
SECRET = "0f8c2a1b" * 8
CI_KEY = "ci-key-literal-long-enough-to-not-warn"


_ISSUED_TODAY = dt.date.today().isoformat()


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


def _build(store_root, **entry):
    """A valid flagged entry, overridable per test."""
    base = dict(break_glass=True, name="alice", key=REF, role="admin")
    base.update(entry)
    return build_static_authenticator(_cfg(store_root, **base))


def _cfg(store_root=None, **entry):
    gateway: dict = {"rbac": [entry]}
    if store_root is not None:
        gateway["credentials"] = {"root": str(store_root)}
    return {"gateway": gateway}


def test_flagged_entry_without_a_name_refuses_to_start(store):
    with pytest.raises(BreakGlassConfigError, match="no name"):
        build_static_authenticator(_cfg(store, break_glass=True, key=REF, role="admin", issued=_ISSUED_TODAY))


def test_a_blank_name_is_not_a_name(store):
    """`name: "   "` is an omitted field wearing a value."""
    with pytest.raises(BreakGlassConfigError, match="no name"):
        build_static_authenticator(
            _cfg(store, break_glass=True, name="   ", key=REF, role="admin", issued=_ISSUED_TODAY)
        )


def test_a_literal_key_is_refused(store):
    with pytest.raises(BreakGlassConfigError, match="literal value"):
        build_static_authenticator(
            _cfg(store, break_glass=True, name="alice", key=SECRET, role="admin", issued=_ISSUED_TODAY)
        )


def test_a_flagged_entry_with_no_key_is_refused(store):
    with pytest.raises(BreakGlassConfigError, match="no key"):
        build_static_authenticator(_cfg(store, break_glass=True, name="alice", role="admin", issued=_ISSUED_TODAY))


def test_no_resolver_configured_is_refused():
    """A secret:// reference with nowhere to resolve it is a broken break-glass path."""
    with pytest.raises(BreakGlassConfigError, match="no credential resolver"):
        build_static_authenticator(
            _cfg(None, break_glass=True, name="alice", key=REF, role="admin", issued=_ISSUED_TODAY)
        )


def test_an_unresolvable_reference_is_refused(store):
    missing = "secret://t-3f9a1c2b7d4e8065/break-glass/bob#key"
    with pytest.raises(BreakGlassConfigError, match="could not be resolved"):
        build_static_authenticator(
            _cfg(store, break_glass=True, name="bob", key=missing, role="admin", issued=_ISSUED_TODAY)
        )


def test_a_world_readable_secret_is_refused(store):
    """The resolver's ownership check is reused, not reimplemented — so it applies here too."""
    (store / "t-3f9a1c2b7d4e8065" / "break-glass" / "alice" / "key").chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    with pytest.raises(BreakGlassConfigError, match="could not be resolved"):
        _build(store, issued=_ISSUED_TODAY)


def test_a_valid_flagged_entry_authenticates_as_the_named_person(store):
    auth = _build(store, issued=_ISSUED_TODAY)
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
    cfg = _cfg(store, break_glass=True, key=REF, role="admin", issued=_ISSUED_TODAY)
    cfg["gateway"]["allow_weak_keys"] = True
    cfg["gateway"]["allow_anonymous"] = True
    with pytest.raises(BreakGlassConfigError):
        build_static_authenticator(cfg)


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses mode checks")
def test_the_resolved_key_never_appears_in_the_config_document(store):
    """The whole point of the reference: the document carries a pointer, not the credential."""
    cfg = _cfg(store, break_glass=True, name="alice", key=REF, role="admin", issued=_ISSUED_TODAY)
    build_static_authenticator(cfg)
    assert SECRET not in repr(cfg), "resolution must not write the material back into config"


# ── ADR-0023 §3: a real lifetime, warned about before it lapses ──────────────────────────


def _issued(days_ago: int) -> str:
    return (dt.date.today() - dt.timedelta(days=days_ago)).isoformat()


def test_a_flagged_entry_without_an_issued_date_is_refused(store):
    """No issue date means indefinite validity — the thing §3 exists to prevent."""
    with pytest.raises(BreakGlassConfigError, match="no 'issued' date"):
        build_static_authenticator(_cfg(store, break_glass=True, name="alice", key=REF, role="admin"))


def test_an_unparseable_issued_date_is_refused(store):
    with pytest.raises(BreakGlassConfigError, match="unparseable"):
        build_static_authenticator(
            _cfg(store, break_glass=True, name="alice", key=REF, role="admin", issued="last tuesday")
        )


def test_a_future_issued_date_is_refused(store):
    """The likeliest cause is a typo in the year, and it silently extends the lifetime."""
    future = (dt.date.today() + dt.timedelta(days=1)).isoformat()
    with pytest.raises(BreakGlassConfigError, match="in the future"):
        build_static_authenticator(_cfg(store, break_glass=True, name="alice", key=REF, role="admin", issued=future))


def test_a_fresh_credential_authenticates(store):
    auth = _build(store, issued=_issued(0))
    assert auth.authenticate(_bearer(SECRET)).subject == "key:alice"


def test_a_credential_one_day_before_expiry_still_works(store):
    auth = _build(store, issued=_issued(89))
    assert auth.authenticate(_bearer(SECRET)).subject == "key:alice"


def test_an_expired_credential_is_dropped_and_does_not_authenticate(store):
    auth = _build(store, issued=_issued(91))
    with pytest.raises(HTTPException) as exc:
        auth.authenticate(_bearer(SECRET))
    assert exc.value.status_code == 401


def test_expiry_day_itself_is_expired(store):
    """Day 90 of a 90-day lifetime has zero remaining. Boundaries decided, not left to luck."""
    auth = _build(store, issued=_issued(90))
    with pytest.raises(HTTPException):
        auth.authenticate(_bearer(SECRET))


def test_an_expired_credential_does_not_stop_the_gateway(store):
    """The judgment call, pinned: expiry drops a key, it does not refuse to boot.

    Refusing to start would turn a credential-hygiene lapse into an outage of the mechanism
    that exists for outages — the operator reaching for break-glass during an IdP failure
    would find the gateway itself refusing to start.
    """
    cfg = _cfg(store, break_glass=True, name="alice", key=REF, role="admin", issued=_issued(200))
    cfg["gateway"]["rbac"].append({"name": "ci", "key": CI_KEY, "role": "viewer"})
    auth = build_static_authenticator(cfg)  # must not raise
    assert auth.authenticate(_bearer(CI_KEY)).subject == "key:ci", "other keys keep working"


def test_the_expiry_term_is_configurable(store):
    """90 is a starting default, not a fixed value (§3)."""
    cfg = _cfg(store, break_glass=True, name="alice", key=REF, role="admin", issued=_issued(45))
    cfg["gateway"]["break_glass_expiry_days"] = 30
    auth = build_static_authenticator(cfg)
    with pytest.raises(HTTPException):
        auth.authenticate(_bearer(SECRET))


@pytest.fixture()
def captured_logs():
    """Capture loguru output. `caplog` does not see it — loguru is not stdlib logging."""
    records: list[str] = []
    sink_id = logger.add(lambda m: records.append(str(m)), level="WARNING")
    try:
        yield records
    finally:
        logger.remove(sink_id)


@pytest.mark.parametrize(
    "days_ago,expect",
    [(0, None), (75, None), (76, "expires in 14 day"), (87, "expires in 3 day"), (89, "expires in 1 day")],
)
def test_the_warning_escalates_as_expiry_approaches(store, captured_logs, days_ago, expect):
    """Two weeks out, then three days out — §3's escalating notice, not a silent cutoff."""
    _build(store, issued=_issued(days_ago))
    warnings = " ".join(captured_logs)
    if expect is None:
        assert "expires in" not in warnings
    else:
        assert expect in warnings


def test_an_expired_only_key_refuses_requests_rather_than_opening_the_gateway(store, captured_logs):
    """The bug this slice nearly shipped, pinned.

    Dropping an expired key left `keys` empty, and an empty key map had always meant "no auth
    configured" — so the single-operator convenience path took over and every request was
    served as ANONYMOUS with *all* scopes. A credential lapsing must produce a 401; it must
    never open the gateway. Configured-but-expired and never-configured are opposite states
    that happened to produce the same count.
    """
    auth = _build(store, issued=_issued(200))
    assert auth.enabled is True, "auth must stay on when a key was configured and expired"
    with pytest.raises(HTTPException) as exc:
        auth.authenticate(None)
    assert exc.value.status_code == 401
    assert any("Auth stays ENABLED" in line for line in captured_logs)


# ── The expiry countdown reaches the metrics plane, not just the startup log ─────────────


def _expiry_gauge(subject: str):
    from device_mcp_gateway import metrics

    return metrics.break_glass_expiry_timestamp_seconds.labels(subject=subject)._value.get()


def test_expiry_is_published_as_an_absolute_timestamp(store):
    """A days-remaining gauge set at startup silently rots.

    The startup log warns at 14 days and again at 3, but a gateway that has not restarted in
    a month never re-emits it — and "discovered dead during the incident it exists for" is
    the exact failure §3 names, arriving through the monitoring instead of the credential.
    An absolute expiry timestamp stays correct without a restart because Prometheus does the
    arithmetic; a days-remaining number would be wrong by however long the process has been
    up.
    """
    _build(store, issued=_issued(30))

    expected = dt.datetime.combine(
        dt.date.today() - dt.timedelta(days=30) + dt.timedelta(days=90),
        dt.time.min,
        tzinfo=dt.timezone.utc,
    ).timestamp()
    assert _expiry_gauge("key:alice") == pytest.approx(expected)


def test_an_expired_entry_keeps_reporting_its_expiry(store):
    """The gauge has to survive the key being dropped, or the alert goes quiet at the loudest
    moment — when the credential has actually lapsed and nobody can use it."""
    _build(store, issued=_issued(200))

    assert _expiry_gauge("key:alice") < dt.datetime.now(dt.timezone.utc).timestamp()
