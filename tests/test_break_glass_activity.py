# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0023 §2/§3 — break-glass use is loud, and reactivation frequency is flagged.

Slices 1 and 2 built a credential that names a person and expires. This is the slice that
finally *reads* ``Principal.break_glass``; until now the fact was carried and nothing
consumed it.

Three properties are load-bearing and each has a test that fails if it regresses:

1. **Every use is audited, every activation notifies — and they are not the same event.**
   Working an incident for hours must produce one activation, not one notification per
   request, or the loud signal is unreadable during exactly the incident it announces.
2. **Nothing ever blocks.** Crossing the reactivation threshold raises a flag and returns
   normally. There is no code path here that can refuse a request, and
   ``test_crossing_the_threshold_flags_and_does_not_block`` exists to keep it that way.
3. **Nothing here can fail a request either.** A tracker that raises, a Redis that is gone —
   break-glass gets reached for *during* infrastructure failures, so observing the path must
   never be able to break it.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from loguru import logger

from device_mcp_gateway.breakglass import (
    InMemoryBreakGlassActivity,
    RedisBreakGlassActivity,
    note_break_glass_use,
)
from device_mcp_gateway.rbac import Authenticator, Principal, authenticate_request, scopes_for_role
from device_mcp_gateway.shared.keys import KEYS

BREAK_GLASS = Principal(
    subject="key:alice",
    scopes=scopes_for_role("admin"),
    auth_method="break_glass",
    break_glass=True,
)
ORDINARY = Principal(subject="key:ci", scopes=scopes_for_role("viewer"), auth_method="api_key")


@pytest.fixture
def audit_log():
    """Emitted audit records (event='audit') as a list of `extra` dicts."""
    captured: list[dict] = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    sink_id = logger.add(_sink, level="INFO")
    yield captured
    logger.remove(sink_id)


@pytest.fixture
def captured_logs():
    """Loguru output at WARNING and above. `caplog` does not see it — this is not stdlib logging."""
    records: list[str] = []
    sink_id = logger.add(lambda m: records.append(str(m)), level="WARNING")
    try:
        yield records
    finally:
        logger.remove(sink_id)


def _state(**overrides):
    """An app.state stand-in with a fresh per-test tracker."""
    state = SimpleNamespace(
        config={"gateway": {}},
        break_glass_activity=InMemoryBreakGlassActivity(),
    )
    for key, value in overrides.items():
        setattr(state, key, value)
    return state


def _of(records, action):
    return [r for r in records if r.get("action") == action]


# ── §2: every use is loud, and distinct from ordinary authentication ─────────────────────


@pytest.mark.asyncio
async def test_every_use_emits_a_high_severity_event_naming_the_person(audit_log):
    await note_break_glass_use(_state(), BREAK_GLASS, rid="rid-1", target="POST /v1/devices")

    uses = _of(audit_log, "auth.break_glass")
    assert len(uses) == 1
    event = uses[0]
    assert event["severity"] == "high"
    assert event["subject"] == "key:alice", "the audit must name the person, never the role"
    assert event["target"] == "POST /v1/devices"
    assert event["rid"] == "rid-1"


@pytest.mark.asyncio
async def test_the_use_event_is_distinct_from_ordinary_static_key_authentication(audit_log):
    """§2's actual requirement: not folded into request logging where it reads as unremarkable."""
    await note_break_glass_use(_state(), BREAK_GLASS)
    actions = {r["action"] for r in audit_log}
    assert "auth.break_glass" in actions
    assert "auth.authenticate" not in actions, "a dedicated action, not the routine one with a field set"


@pytest.mark.asyncio
async def test_an_ordinary_key_produces_none_of_this(audit_log):
    """The flag is selective by design — CI keys and machine credentials stay quiet."""
    state = _state()
    request = _fake_request(Authenticator({"ci-token": ORDINARY}, enabled=True), state)
    await authenticate_request(request, _bearer("ci-token"))

    assert _of(audit_log, "auth.break_glass") == []
    assert _of(audit_log, "auth.break_glass.activated") == []


# ── §3: an activation is a session, not a request ────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_worked_incident_is_one_activation_however_many_calls_it_takes(audit_log):
    """The property the notification hangs on.

    §3 forbids throttling within an active session because a real incident may need many
    calls over hours. Notifying per request would be the same mistake wearing different
    clothes: the alert that fires 400 times is not a louder alert, it is an unreadable one.
    """
    state = _state()
    for _ in range(20):
        await note_break_glass_use(state, BREAK_GLASS)

    assert len(_of(audit_log, "auth.break_glass")) == 20, "every use stays in the audit chain"
    assert len(_of(audit_log, "auth.break_glass.activated")) == 1, "one incident, one notification"


@pytest.mark.asyncio
async def test_a_use_after_the_quiet_gap_is_a_new_activation(audit_log):
    state = _state(config={"gateway": {"break_glass_session_gap_minutes": 0}})
    await note_break_glass_use(state, BREAK_GLASS)
    await note_break_glass_use(state, BREAK_GLASS)

    activations = _of(audit_log, "auth.break_glass.activated")
    assert len(activations) == 2
    assert activations[1]["activations_in_window"] == 2


@pytest.mark.asyncio
async def test_the_activation_event_carries_the_history_that_makes_it_actionable(audit_log):
    """ "Someone used break-glass" is a fact; "and they also used it 6 days ago" is a decision."""
    state = _state(config={"gateway": {"break_glass_session_gap_minutes": 0}})
    tracker = state.break_glass_activity
    await note_break_glass_use(state, BREAK_GLASS)
    # Rewind the recorded use by six days without waiting six days.
    last_use, activations, window_expires = tracker._seen["key:alice"]
    tracker._seen["key:alice"] = (last_use - 6 * 86400, activations, window_expires)

    await note_break_glass_use(state, BREAK_GLASS)

    event = _of(audit_log, "auth.break_glass.activated")[-1]
    assert event["days_since_last_use"] == pytest.approx(6.0, abs=0.01)
    assert event["review_window_days"] == 30
    assert event["severity"] == "critical"


@pytest.mark.asyncio
async def test_an_activation_writes_a_durable_tenant_notification():
    """ADR-0017 slice 5, closing the confirmed ADR-0023 gap: until now an activation only ever
    reached an audit event, a metric and a log line — nothing a tenant admin who isn't watching
    Prometheus would see."""
    state = _state(config={"gateway": {"break_glass_session_gap_minutes": 0}})

    await note_break_glass_use(state, BREAK_GLASS)

    notifications = await state.tenant_notifications.list_recent()
    [only] = notifications
    assert only.kind == "break_glass.activated"
    assert only.subject == "key:alice"
    assert "key:alice" in only.message


@pytest.mark.asyncio
async def test_a_routine_use_within_a_session_writes_no_second_notification():
    """Same reasoning as the audit split: one incident is one notification, however many
    calls it takes — not one per request."""
    state = _state(config={"gateway": {"break_glass_session_gap_minutes": 60}})

    await note_break_glass_use(state, BREAK_GLASS)
    await note_break_glass_use(state, BREAK_GLASS)  # inside the same session — routine, not an activation

    assert len(await state.tenant_notifications.list_recent()) == 1


# ── §3: flag, never hard-block ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_crossing_the_threshold_flags_and_does_not_block(audit_log, captured_logs):
    """The one behaviour §3 is most explicit about.

    "A fixed low call limit could cut off a legitimate incident response mid-session, the
    exact failure mode a mechanism meant to work when everything else is broken cannot
    afford." So this asserts two things at once: the flag is raised, AND the call returns
    normally rather than raising, refusing, or degrading the principal.
    """
    state = _state(config={"gateway": {"break_glass_session_gap_minutes": 0, "break_glass_review_threshold": 3}})
    for _ in range(5):
        await note_break_glass_use(state, BREAK_GLASS)  # must not raise

    activations = _of(audit_log, "auth.break_glass.activated")
    assert [e["review_flag"] for e in activations] == [False, False, False, True, True]
    assert "REACTIVATION FLAG" in " ".join(captured_logs)


@pytest.mark.asyncio
async def test_a_flagged_credential_still_authenticates_afterwards(audit_log):
    """Flagging is a review signal. The next request — possibly a second real emergency —
    must be served exactly as before."""
    state = _state(config={"gateway": {"break_glass_session_gap_minutes": 0, "break_glass_review_threshold": 1}})
    auth = Authenticator({"bg-token": BREAK_GLASS}, enabled=True)
    for _ in range(4):
        request = _fake_request(auth, state)
        await authenticate_request(request, _bearer("bg-token"))
        assert request.state.principal.scopes == scopes_for_role("admin"), "scope is never narrowed"

    assert any(e["review_flag"] for e in _of(audit_log, "auth.break_glass.activated"))


# ── Observing the emergency path must never break it ─────────────────────────────────────


class _BrokenTracker:
    async def record(self, subject, *, gap_seconds, window_seconds):
        raise RuntimeError("Redis is gone")


@pytest.mark.asyncio
async def test_a_broken_tracker_does_not_fail_the_request(audit_log, captured_logs):
    """Break-glass is reached for *during* infrastructure failures, so "the tracker is down"
    is not an edge case — it is a substantial fraction of the times this code runs."""
    state = _state(break_glass_activity=_BrokenTracker())
    auth = Authenticator({"bg-token": BREAK_GLASS}, enabled=True)
    request = _fake_request(auth, state)

    await authenticate_request(request, _bearer("bg-token"))  # must not raise

    assert request.state.principal.break_glass is True
    assert len(_of(audit_log, "auth.break_glass")) == 1, "attribution survives a dead tracker"
    assert "Break-glass event emission failed" in " ".join(captured_logs)


@pytest.mark.asyncio
async def test_an_app_with_no_tracker_wired_still_emits_the_events(audit_log):
    """An app built without the wiring (a test, an embedded host) is exactly the setup least
    likely to notice a silently-quiet loud path."""
    state = SimpleNamespace(config={"gateway": {}})
    await note_break_glass_use(state, BREAK_GLASS)

    assert len(_of(audit_log, "auth.break_glass")) == 1
    assert len(_of(audit_log, "auth.break_glass.activated")) == 1
    assert isinstance(state.break_glass_activity, InMemoryBreakGlassActivity), "created and kept"


@pytest.mark.asyncio
async def test_a_state_object_that_refuses_attributes_is_survivable(audit_log):
    class _Frozen:
        __slots__ = ("config",)

        def __init__(self):
            self.config = {"gateway": {}}

    await note_break_glass_use(_Frozen(), BREAK_GLASS)
    assert len(_of(audit_log, "auth.break_glass")) == 1


# ── The composite (OIDC) path — the one easiest to miss ──────────────────────────────────


@pytest.mark.asyncio
async def test_the_oidc_fall_through_to_a_break_glass_key_is_just_as_loud(audit_log):
    """The case that matters most.

    In an OIDC deployment the static key is only reached when the JWT path fails or is
    absent — that fall-through IS the break-glass event. Hanging the hook off the resolved
    Principal rather than off the static authenticator is what makes this work without a
    second call site to remember.
    """
    from device_mcp_gateway.rbac import CompositeAuthenticator

    class _DeadIdP:
        async def validate(self, token):
            from device_mcp_gateway.oidc import OIDCError

            raise OIDCError("JWKS endpoint unreachable")

    composite = CompositeAuthenticator(static=Authenticator({"bg-token": BREAK_GLASS}, enabled=True), oidc=_DeadIdP())
    request = _fake_request(composite, _state())
    await authenticate_request(request, _bearer("bg-token"))

    assert request.state.principal.subject == "key:alice"
    assert len(_of(audit_log, "auth.break_glass")) == 1
    assert len(_of(audit_log, "auth.break_glass.activated")) == 1


# ── The in-memory tracker's own semantics ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_window_count_starts_clean_after_a_full_quiet_window():
    """The reason the window key expires at all: a credential nobody has touched for a full
    window is not "still over the threshold from six months ago"."""
    tracker = InMemoryBreakGlassActivity()
    first = await tracker.record("key:alice", gap_seconds=0, window_seconds=60)
    assert first.activations == 1

    last_use, activations, _ = tracker._seen["key:alice"]
    tracker._seen["key:alice"] = (last_use, activations, time.time() - 1)  # window already elapsed

    second = await tracker.record("key:alice", gap_seconds=0, window_seconds=60)
    assert second.activations == 1, "the count restarted rather than continuing to climb"


@pytest.mark.asyncio
async def test_two_credentials_are_counted_independently():
    """Per-person revocation is the payoff of slice 1; per-person *signal* is the payoff here."""
    tracker = InMemoryBreakGlassActivity()
    for _ in range(3):
        await tracker.record("key:alice", gap_seconds=0, window_seconds=3600)
    bob = await tracker.record("key:bob", gap_seconds=0, window_seconds=3600)
    assert bob.activations == 1


# ── The Redis tracker, against real Redis ────────────────────────────────────────────────
#
# fakeredis cannot carry these: the session-gap semantics rest on a key's TTL actually
# expiring, and the cross-replica property rests on two clients seeing one keyspace. Both are
# the sort of claim that reads as obviously true and has been measurably false in this project
# before, so they are asserted against the real server or skipped, never stubbed.


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_tracker_counts_one_activation_across_two_replicas(real_redis):
    """The entire reason this state is not process-local: two gateway replicas serving one
    incident must produce one notification, not one each."""
    replica_a = RedisBreakGlassActivity(real_redis)
    replica_b = RedisBreakGlassActivity(real_redis)

    first = await replica_a.record("key:alice", gap_seconds=60, window_seconds=3600)
    second = await replica_b.record("key:alice", gap_seconds=60, window_seconds=3600)

    assert first.activation is True
    assert second.activation is False, "the second replica joined an active session"
    assert first.degraded is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_the_session_marker_really_expires_and_reopens_an_activation(real_redis):
    """The TTL *is* the mechanism, not a cleanup detail — so it is tested where TTLs are real."""
    tracker = RedisBreakGlassActivity(real_redis)
    await tracker.record("key:alice", gap_seconds=1, window_seconds=3600)
    assert await real_redis.ttl(KEYS.break_glass_session("key:alice")) > 0

    await asyncio.sleep(1.2)
    reactivated = await tracker.record("key:alice", gap_seconds=1, window_seconds=3600)

    assert reactivated.activation is True
    assert reactivated.activations == 2, "the window counter carried across the session boundary"
    assert reactivated.seconds_since_last_use == pytest.approx(1.2, abs=0.5)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_the_review_window_slides_from_the_last_activation(real_redis):
    """Not a fixed window. A credential activating every week is precisely the tell §3 asks
    to watch, and a window that reset on a fixed boundary would zero the count underneath it.

    This test was vacuous when first written — it used ``gap_seconds=0``, which made every
    Redis call raise and fall through to the in-process tracker, so it asserted ``-2 >= -2``
    about a key that was never created. It passed with the window logic inverted, which is
    how the ``EX 0`` defect below was found. It now proves the TTL was actually pushed out.
    """
    tracker = RedisBreakGlassActivity(real_redis)
    window_key = KEYS.break_glass_window("key:alice")
    await tracker.record("key:alice", gap_seconds=1, window_seconds=100)
    first_ttl = await real_redis.ttl(window_key)
    assert first_ttl > 0, "the window key must exist, or this test proves nothing"

    await asyncio.sleep(1.2)
    reactivated = await tracker.record("key:alice", gap_seconds=1, window_seconds=100)
    second_ttl = await real_redis.ttl(window_key)

    assert reactivated.activation is True, "the session marker lapsed, so this is a new activation"
    assert first_ttl - second_ttl < 1, f"window did not slide: {first_ttl} -> {second_ttl}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_zero_session_gap_does_not_break_the_redis_tracker(real_redis):
    """A defect a passing test hid.

    `break_glass_session_gap_minutes: 0` is a legitimate setting — "notify on every use" —
    and it is NOT expressible as a TTL: Redis rejects `EX 0` outright. Unhandled, it raised
    on every request, and the fall-back-to-process-local path turned that into silent
    per-replica counting plus a warning per call, during an incident, which is the only time
    any of this runs. Skipping the marker is what a zero-length session means.
    """
    tracker = RedisBreakGlassActivity(real_redis)

    first = await tracker.record("key:alice", gap_seconds=0, window_seconds=3600)
    second = await tracker.record("key:alice", gap_seconds=0, window_seconds=3600)

    assert (first.degraded, second.degraded) == (False, False), "no fall-back: Redis handled it"
    assert (first.activation, second.activation) == (True, True), "every use is its own activation"
    assert second.activations == 2, "and they accumulate in the shared window, not per replica"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_dead_redis_degrades_to_process_local_rather_than_losing_the_signal(real_redis):
    """An outage is when break-glass gets used. Losing the activation signal exactly then
    would be the worst possible time for the observability to go quiet."""

    class _DeadRedis:
        async def set(self, *a, **kw):
            raise ConnectionError("connection refused")

    tracker = RedisBreakGlassActivity(_DeadRedis())
    activity = await tracker.record("key:alice", gap_seconds=60, window_seconds=3600)

    assert activity.activation is True
    assert activity.degraded is True, "reported as degraded rather than passed off as authoritative"
    assert (await tracker.record("key:alice", gap_seconds=60, window_seconds=3600)).activation is False


# --- helpers -----------------------------------------------------------------


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _fake_request(authenticator, app_state, *, rid="rid-1", method="POST", path="/v1/devices"):
    app_state.authenticator = authenticator
    return SimpleNamespace(
        app=SimpleNamespace(state=app_state),
        state=SimpleNamespace(request_id=rid),
        method=method,
        url=SimpleNamespace(path=path),
    )
