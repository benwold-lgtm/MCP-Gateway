# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017, slice 0 — the store layer, in isolation.

No route calls any of this yet. What has to be right here, before anything is wired to it:

1. A `PendingSupportRequest` behaves like `write_planned.PendingProposal`'s tracker — lazy
   expiry, no background sweep, degrades to process-local state on a Redis error.
2. A poll is scoped strictly to the raising `provider_subject` — a mismatch reads exactly like
   the request never existed, never "found but not yours" (ADR-0017 §7's resolved question).
3. Delivery is one-shot: the first successful poll after a decision consumes and deletes the
   record; a second poll for the same id gets `not_found`.
4. Two admins deciding the same request concurrently can only ever have one winner — the same
   atomic-race-winner property `write_planned.py` already proves against real Redis `HSETNX`,
   proven here the same way rather than assumed to transfer.
5. A `SupportGrant` is checked *live*, potentially many times over its window — `check` never
   consumes anything; only a human calling `revoke` mutates a live grant, and every distinct
   refusal reason (`not_found`, `expired`, `revoked`) is observably different.
"""

from __future__ import annotations

import asyncio

import pytest

from device_mcp_gateway.cfg import (
    _defaults,
    support_grant_ttl_seconds,
    support_request_ttl_seconds,
    support_standing_consent_max_seconds,
    validate_config,
)
from device_mcp_gateway.shared.keys import KEYS
from device_mcp_gateway.support_grants import (
    InMemoryPendingSupportRequestStore,
    InMemoryStandingConsentStore,
    InMemorySupportGrantStore,
    RedisPendingSupportRequestStore,
    RedisStandingConsentStore,
    RedisSupportGrantStore,
    pending_support_request_store,
    standing_consent_store,
    support_grant_store,
)

SCOPES = frozenset({"devices:read", "tools:call"})


# --- config -------------------------------------------------------------------------------


def test_defaults_are_well_formed_and_pass_validation():
    cfg = _defaults()
    assert cfg["support_requests"]["request_ttl_seconds"] == 300
    assert cfg["support_requests"]["grant_ttl_seconds"] == 60 * 60
    assert cfg["support_requests"]["standing_consent_max_seconds"] == 90 * 24 * 60 * 60
    assert validate_config(cfg) == []


def test_accessors_read_configured_values():
    cfg = {"support_requests": {"request_ttl_seconds": 60, "grant_ttl_seconds": 120, "standing_consent_max_seconds": 5}}
    assert support_request_ttl_seconds(cfg) == 60
    assert support_grant_ttl_seconds(cfg) == 120
    assert support_standing_consent_max_seconds(cfg) == 5


def test_accessors_fall_back_to_defaults_on_an_empty_or_zero_config():
    assert support_request_ttl_seconds({}) == 300
    assert support_grant_ttl_seconds({}) == 60 * 60
    assert support_standing_consent_max_seconds({}) == 90 * 24 * 60 * 60
    assert support_grant_ttl_seconds({"support_requests": {"grant_ttl_seconds": 0}}) == 60 * 60


def test_an_unknown_support_requests_key_is_flagged_not_silently_ignored():
    problems = validate_config({"support_requests": {"typo_ttl_seconds": 1}})
    assert any("support_requests.typo_ttl_seconds" in p for p in problems)


# --- pending request store: in-memory -------------------------------------------------------


@pytest.mark.asyncio
async def test_a_created_request_is_visible_to_a_reviewer():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(
        provider_subject="oidc:provider-idp#op1", requested_scopes=SCOPES, justification="INC-1", ttl_seconds=60
    )
    request = await store.get(request_id)
    assert request is not None
    assert request.request_id == request_id
    assert request.provider_subject == "oidc:provider-idp#op1"
    assert request.requested_scopes == SCOPES
    assert request.justification == "INC-1"
    assert request.degraded is False


@pytest.mark.asyncio
async def test_an_unknown_request_id_is_none():
    store = InMemoryPendingSupportRequestStore()
    assert await store.get("never-created") is None


@pytest.mark.asyncio
async def test_an_expired_request_reads_as_gone():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(
        provider_subject="oidc:provider-idp#op1", requested_scopes=SCOPES, justification="INC-1", ttl_seconds=-1
    )
    assert await store.get(request_id) is None


@pytest.mark.asyncio
async def test_two_requests_get_distinct_unguessable_ids():
    store = InMemoryPendingSupportRequestStore()
    a = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    b = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="b", ttl_seconds=60)
    assert a != b
    assert len(a) > 16 and len(b) > 16


# --- list_pending: the tenant console's inbox ------------------------------------------------


@pytest.mark.asyncio
async def test_list_pending_shows_a_freshly_created_request():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)

    listed = await store.list_pending()

    assert [r.request_id for r in listed] == [request_id]


@pytest.mark.asyncio
async def test_list_pending_excludes_a_decided_request():
    """The moment a request is decided it leaves the reviewer's inbox — showing it again
    would look undone, even though it lingers (undelivered) for the operator's poll."""
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    await store.mark_approved(request_id, grant_id="g1", credential="tok")

    assert await store.list_pending() == []


@pytest.mark.asyncio
async def test_list_pending_excludes_an_expired_request():
    store = InMemoryPendingSupportRequestStore()
    await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=-1)
    assert await store.list_pending() == []


# --- poll: the session-bound delivery property ----------------------------------------------


@pytest.mark.asyncio
async def test_poll_reports_pending_without_consuming():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)

    first = await store.poll(request_id, provider_subject="op1")
    second = await store.poll(request_id, provider_subject="op1")

    assert first.status == "pending"
    assert second.status == "pending", "polling while pending must not consume the record"


@pytest.mark.asyncio
async def test_poll_from_a_different_subject_reads_as_not_found():
    """The whole point of §7's resolved polling question: a mismatch must not disclose that
    someone else's request exists at all."""
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)

    result = await store.poll(request_id, provider_subject="op2")

    assert (result.status, result.reason) == (None, "not_found")


@pytest.mark.asyncio
async def test_an_approved_requests_credential_is_delivered_exactly_once():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    assert await store.mark_approved(request_id, grant_id="g1", credential="tok-abc") is True

    first = await store.poll(request_id, provider_subject="op1")
    second = await store.poll(request_id, provider_subject="op1")

    assert (first.status, first.grant_id, first.credential) == ("approved", "g1", "tok-abc")
    assert (second.status, second.reason) == (None, "not_found"), "a second poll must not re-deliver the credential"


@pytest.mark.asyncio
async def test_a_rejected_request_is_reported_once_then_gone():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    assert await store.mark_rejected(request_id) is True

    first = await store.poll(request_id, provider_subject="op1")
    second = await store.poll(request_id, provider_subject="op1")

    assert first.status == "rejected"
    assert (second.status, second.reason) == (None, "not_found")


@pytest.mark.asyncio
async def test_a_request_cannot_be_decided_twice():
    store = InMemoryPendingSupportRequestStore()
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    assert await store.mark_approved(request_id, grant_id="g1", credential="tok-abc") is True

    # Already approved (and not yet polled) — a second decision must not silently overwrite it.
    assert await store.mark_rejected(request_id) is False


@pytest.mark.asyncio
async def test_deciding_an_unknown_request_reports_false_not_an_exception():
    store = InMemoryPendingSupportRequestStore()
    assert await store.mark_approved("never-created", grant_id="g1", credential="tok") is False
    assert await store.mark_rejected("never-created") is False


# --- grant store: in-memory ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_live_grant_checks_ok_repeatedly():
    """The core structural difference from write_planned's single-use grant: checking never
    consumes."""
    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)

    results = [await store.check(grant.id) for _ in range(5)]

    assert all(r.ok for r in results)


@pytest.mark.asyncio
async def test_no_grant_at_all_is_not_found():
    store = InMemorySupportGrantStore()
    result = await store.check("never-issued")
    assert (result.ok, result.reason, result.grant) == (False, "not_found", None)


@pytest.mark.asyncio
async def test_an_expired_grant_is_refused_as_expired():
    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=-1)
    result = await store.check(grant.id)
    assert result.reason == "expired"


@pytest.mark.asyncio
async def test_revoking_a_live_grant_ends_it_immediately():
    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)

    revoke_result = await store.revoke(grant.id)
    check_result = await store.check(grant.id)

    assert revoke_result.ok is True
    assert (check_result.ok, check_result.reason) == (False, "revoked")


@pytest.mark.asyncio
async def test_revoking_twice_is_reported_not_raised():
    """A tenant admin clicking revoke a second time must never see an error."""
    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)
    await store.revoke(grant.id)

    second = await store.revoke(grant.id)

    assert (second.ok, second.reason) == (False, "revoked")


@pytest.mark.asyncio
async def test_revoking_an_unknown_grant_is_not_found():
    store = InMemorySupportGrantStore()
    result = await store.revoke("never-issued")
    assert (result.ok, result.reason) == (False, "not_found")


@pytest.mark.asyncio
async def test_self_issued_and_step_up_flags_round_trip():
    store = InMemorySupportGrantStore()
    grant = await store.issue(
        provider_subject="op1", scopes=SCOPES, ttl_seconds=60, step_up_verified=True, self_issued=True
    )
    result = await store.check(grant.id)
    assert result.grant.step_up_verified is True
    assert result.grant.self_issued is True


# --- list_active: "who can reach my stack right now" ------------------------------------------


@pytest.mark.asyncio
async def test_list_active_shows_a_freshly_issued_grant():
    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)

    listed = await store.list_active()

    assert [g.id for g in listed] == [grant.id]


@pytest.mark.asyncio
async def test_list_active_excludes_a_revoked_grant():
    store = InMemorySupportGrantStore()
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)
    await store.revoke(grant.id)

    assert await store.list_active() == []


@pytest.mark.asyncio
async def test_list_active_excludes_an_expired_grant():
    store = InMemorySupportGrantStore()
    await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=-1)
    assert await store.list_active() == []


# --- standing consent: in-memory ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_enabling_standing_consent_round_trips():
    store = InMemoryStandingConsentStore()
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=60)

    consent = await store.get()

    assert consent is not None
    assert consent.scopes == SCOPES
    assert consent.enabled_by == "admin1"
    assert consent.degraded is False


@pytest.mark.asyncio
async def test_no_standing_consent_ever_enabled_is_none():
    store = InMemoryStandingConsentStore()
    assert await store.get() is None


@pytest.mark.asyncio
async def test_a_lapsed_standing_consent_reads_as_none():
    store = InMemoryStandingConsentStore()
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=-1)
    assert await store.get() is None


@pytest.mark.asyncio
async def test_disabling_standing_consent_reports_whether_anything_was_on():
    store = InMemoryStandingConsentStore()
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=60)

    first = await store.disable()
    second = await store.disable()

    assert (first, second) == (True, False)
    assert await store.get() is None


@pytest.mark.asyncio
async def test_re_enabling_replaces_the_prior_setting():
    store = InMemoryStandingConsentStore()
    await store.enable(scopes=frozenset({"devices:read"}), enabled_by="admin1", ttl_seconds=60)
    await store.enable(scopes=frozenset({"tools:call"}), enabled_by="admin2", ttl_seconds=60)

    consent = await store.get()

    assert consent.scopes == frozenset({"tools:call"})
    assert consent.enabled_by == "admin2"


# --- the Redis stores, against real Redis -------------------------------------------------
#
# Same reasoning as test_write_planned.py's own Redis section: the atomicity claim rests on a
# real HSETNX race and a real TTL actually expiring, which fakeredis cannot stand in for
# credibly — assert against the real server or skip, never stub.


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_request_store_round_trips(real_redis):
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(
        provider_subject="op1", requested_scopes=SCOPES, justification="INC-1", ttl_seconds=60
    )

    request = await store.get(request_id)

    assert request is not None
    assert request.requested_scopes == SCOPES
    assert request.degraded is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_request_ttl_really_expires(real_redis):
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=1)
    assert await store.get(request_id) is not None

    await asyncio.sleep(1.3)

    assert await store.get(request_id) is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_poll_delivers_the_credential_exactly_once(real_redis):
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    assert await store.mark_approved(request_id, grant_id="g1", credential="tok-abc") is True

    first = await store.poll(request_id, provider_subject="op1")
    second = await store.poll(request_id, provider_subject="op1")

    assert (first.status, first.credential) == ("approved", "tok-abc")
    assert (second.status, second.reason) == (None, "not_found")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_list_pending_shows_a_freshly_created_request(real_redis):
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)

    listed = await store.list_pending()

    assert [r.request_id for r in listed] == [request_id]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_list_pending_excludes_a_decided_request(real_redis):
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    await store.mark_approved(request_id, grant_id="g1", credential="tok")

    assert await store.list_pending() == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_list_pending_self_heals_a_naturally_expired_member(real_redis):
    """The index and the hash expire independently — a member whose hash Redis already
    reaped must be dropped from the index here, not surfaced as a phantom pending request."""
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=1)
    await asyncio.sleep(1.3)

    listed = await store.list_pending()

    assert listed == []
    assert not await real_redis.sismember(KEYS.support_pending_index, request_id)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_concurrent_decisions_on_one_request_have_exactly_one_winner(real_redis):
    """The proof the whole design rests on: `HSETNX`'s atomicity, not asyncio's — two admins
    deciding the same request at once must produce exactly one winning decision."""
    store = RedisPendingSupportRequestStore(real_redis)
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)

    results = await asyncio.gather(
        *[store.mark_approved(request_id, grant_id=f"g{i}", credential=f"tok{i}") for i in range(10)],
        *[store.mark_rejected(request_id) for _ in range(10)],
    )

    assert sum(1 for r in results if r) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_grant_store_concurrent_revoke_has_exactly_one_winner(real_redis):
    store = RedisSupportGrantStore(real_redis)
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)

    results = await asyncio.gather(*[store.revoke(grant.id) for _ in range(20)])

    winners = [r for r in results if r.ok]
    assert len(winners) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_grant_ttl_really_expires(real_redis):
    store = RedisSupportGrantStore(real_redis)
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=1)
    assert (await store.check(grant.id)).ok is True

    await asyncio.sleep(1.3)

    result = await store.check(grant.id)
    assert result.reason in ("expired", "not_found"), "Redis may have already reaped the key via its own TTL"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_list_active_shows_a_freshly_issued_grant(real_redis):
    store = RedisSupportGrantStore(real_redis)
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)

    listed = await store.list_active()

    assert [g.id for g in listed] == [grant.id]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_list_active_excludes_a_revoked_grant(real_redis):
    store = RedisSupportGrantStore(real_redis)
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)
    await store.revoke(grant.id)

    assert await store.list_active() == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_list_active_self_heals_a_naturally_expired_member(real_redis):
    store = RedisSupportGrantStore(real_redis)
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=1)
    await asyncio.sleep(1.3)

    listed = await store.list_active()

    assert listed == []
    assert not await real_redis.sismember(KEYS.support_active_grants_index, grant.id)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_standing_consent_round_trips(real_redis):
    store = RedisStandingConsentStore(real_redis)
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=60)

    consent = await store.get()

    assert consent is not None
    assert consent.scopes == SCOPES
    assert consent.enabled_by == "admin1"
    assert consent.degraded is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_standing_consent_ttl_really_expires(real_redis):
    store = RedisStandingConsentStore(real_redis)
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=1)
    assert await store.get() is not None

    await asyncio.sleep(1.3)

    assert await store.get() is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_disabling_standing_consent_reports_whether_anything_was_on(real_redis):
    store = RedisStandingConsentStore(real_redis)
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=60)

    first = await store.disable()
    second = await store.disable()

    assert (first, second) == (True, False)


# --- the Redis stores degrade rather than fail the caller -----------------------------------


class _DeadRedis:
    def pipeline(self, transaction=True):
        raise ConnectionError("redis is gone")

    async def hgetall(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def hset(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def hsetnx(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def delete(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def smembers(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def srem(self, *a, **kw):
        raise ConnectionError("redis is gone")


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_the_request_store_rather_than_raising():
    store = RedisPendingSupportRequestStore(_DeadRedis())
    request_id = await store.create(
        provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60
    )  # must not raise

    request = await store.get(request_id)

    assert request is not None
    assert request.degraded is True


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_list_pending_rather_than_raising():
    store = RedisPendingSupportRequestStore(_DeadRedis())
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)

    listed = await store.list_pending()

    assert [r.request_id for r in listed] == [request_id]
    assert listed[0].degraded is True


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_the_grant_store_rather_than_raising():
    store = RedisSupportGrantStore(_DeadRedis())
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)
    assert grant.degraded is True

    result = await store.check(grant.id)

    assert result.ok is True
    assert result.degraded is True


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_list_active_rather_than_raising():
    store = RedisSupportGrantStore(_DeadRedis())
    grant = await store.issue(provider_subject="op1", scopes=SCOPES, ttl_seconds=60)

    listed = await store.list_active()

    assert [g.id for g in listed] == [grant.id]
    assert listed[0].degraded is True


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_standing_consent_rather_than_raising():
    store = RedisStandingConsentStore(_DeadRedis())
    await store.enable(scopes=SCOPES, enabled_by="admin1", ttl_seconds=60)

    consent = await store.get()

    assert consent is not None
    assert consent.degraded is True


@pytest.mark.asyncio
async def test_degraded_poll_still_delivers_exactly_once_within_the_process():
    """The fallback's guarantee is process-local, not cluster-wide — but within the one
    process that is degraded, one-shot delivery must still mean one-shot."""
    store = RedisPendingSupportRequestStore(_DeadRedis())
    request_id = await store.create(provider_subject="op1", requested_scopes=SCOPES, justification="a", ttl_seconds=60)
    await store.mark_approved(request_id, grant_id="g1", credential="tok-abc")

    first = await store.poll(request_id, provider_subject="op1")
    second = await store.poll(request_id, provider_subject="op1")

    assert (first.status, first.degraded) == ("approved", True)
    assert (second.status, second.reason) == (None, "not_found")


# --- the app.state lazy-fallback getters -----------------------------------------------------


def test_pending_support_request_store_creates_and_keeps_one_when_nothing_was_wired():
    from types import SimpleNamespace

    state = SimpleNamespace()
    store = pending_support_request_store(state)
    assert isinstance(store, InMemoryPendingSupportRequestStore)
    assert pending_support_request_store(state) is store, "created once, reused after"


def test_support_grant_store_creates_and_keeps_one_when_nothing_was_wired():
    from types import SimpleNamespace

    state = SimpleNamespace()
    store = support_grant_store(state)
    assert isinstance(store, InMemorySupportGrantStore)
    assert support_grant_store(state) is store, "created once, reused after"


def test_standing_consent_store_creates_and_keeps_one_when_nothing_was_wired():
    from types import SimpleNamespace

    state = SimpleNamespace()
    store = standing_consent_store(state)
    assert isinstance(store, InMemoryStandingConsentStore)
    assert standing_consent_store(state) is store, "created once, reused after"


def test_lazy_getters_survive_a_state_object_that_refuses_new_attributes():
    class _Frozen:
        __slots__ = ()

    frozen = _Frozen()
    store = pending_support_request_store(frozen)  # must not raise
    assert isinstance(store, InMemoryPendingSupportRequestStore)
