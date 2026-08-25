# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0022, slice 1 — the store layer, in isolation.

No route calls any of this yet. What has to be right here, before anything is wired to it:

1. A `PendingProposal` behaves like `BreakGlassActivity`'s tracker — lazy expiry, no
   background sweep, degrades to process-local state on a Redis error rather than failing
   the caller.
2. A single-use `Grant` can be redeemed exactly once, and *which* attempt wins under
   concurrency is decided by one atomic store operation, not by an earlier read — the same
   TOCTOU property `_run_restore` closes for restore's apply, proven here against the real
   Redis `HSETNX` primitive, not simulated.
3. A repeatable `Grant` survives unlimited redemption by the same subject and refuses every
   other subject, unconditionally.
4. Every distinct refusal reason (`not_found`, `expired`, `subject_mismatch`, `consumed`) is
   observably different, because a caller auditing an Apply refusal needs to say which one
   happened, not just that one did.
"""

from __future__ import annotations

import asyncio

import pytest

from device_mcp_gateway.cfg import (
    _defaults,
    validate_config,
    write_planned_grant_ttl_seconds,
    write_planned_proposal_ttl_seconds,
    write_planned_repeatable_max_seconds,
)
from device_mcp_gateway.write_planned import (
    InMemoryPendingProposalStore,
    InMemoryWritePlannedGrantStore,
    RedisPendingProposalStore,
    RedisWritePlannedGrantStore,
    pending_proposal_store,
    write_planned_grant_store,
)

PLAN = {"intent": "register", "hostname": "sensor-1", "base_url": "http://sensor-1.example/"}


# --- config -------------------------------------------------------------------------------


def test_defaults_are_well_formed_and_pass_validation():
    cfg = _defaults()
    assert cfg["write_planned"]["proposal_ttl_seconds"] == 3600
    assert cfg["write_planned"]["grant_ttl_seconds"] == 24 * 60 * 60
    assert cfg["write_planned"]["repeatable_grant_max_seconds"] == 30 * 24 * 60 * 60
    assert validate_config(cfg) == []


def test_accessors_read_configured_values():
    cfg = {"write_planned": {"proposal_ttl_seconds": 60, "grant_ttl_seconds": 120, "repeatable_grant_max_seconds": 5}}
    assert write_planned_proposal_ttl_seconds(cfg) == 60
    assert write_planned_grant_ttl_seconds(cfg) == 120
    assert write_planned_repeatable_max_seconds(cfg) == 5


def test_accessors_fall_back_to_defaults_on_an_empty_or_zero_config():
    assert write_planned_proposal_ttl_seconds({}) == 3600
    assert write_planned_grant_ttl_seconds({}) == 24 * 60 * 60
    assert write_planned_repeatable_max_seconds({}) == 30 * 24 * 60 * 60
    # `or default` reads a configured 0 the same way it reads absence — deliberate, matching
    # `plan_digest_validity_seconds`'s own precedent, since a 0-second grant is meaningless.
    assert write_planned_grant_ttl_seconds({"write_planned": {"grant_ttl_seconds": 0}}) == 24 * 60 * 60


def test_an_unknown_write_planned_key_is_flagged_not_silently_ignored():
    problems = validate_config({"write_planned": {"typo_ttl_seconds": 1}})
    assert any("write_planned.typo_ttl_seconds" in p for p in problems)


# --- pending proposal store: in-memory ------------------------------------------------------


@pytest.mark.asyncio
async def test_a_created_proposal_round_trips():
    store = InMemoryPendingProposalStore()
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=60)
    proposal = await store.get(proposal_id)
    assert proposal is not None
    assert (proposal.subject, proposal.digest, proposal.plan) == ("key:agent1", "d1", PLAN)
    assert proposal.degraded is False


@pytest.mark.asyncio
async def test_an_unknown_proposal_id_is_none():
    store = InMemoryPendingProposalStore()
    assert await store.get("never-created") is None


@pytest.mark.asyncio
async def test_a_deleted_proposal_is_gone():
    store = InMemoryPendingProposalStore()
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=60)
    await store.delete(proposal_id)
    assert await store.get(proposal_id) is None


@pytest.mark.asyncio
async def test_deleting_an_already_gone_proposal_does_not_raise():
    store = InMemoryPendingProposalStore()
    await store.delete("never-created")  # must not raise


@pytest.mark.asyncio
async def test_an_expired_proposal_reads_as_gone():
    store = InMemoryPendingProposalStore()
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=-1)
    assert await store.get(proposal_id) is None


@pytest.mark.asyncio
async def test_two_proposals_get_distinct_unguessable_ids():
    store = InMemoryPendingProposalStore()
    a = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=60)
    b = await store.create(subject="key:agent1", digest="d2", plan=PLAN, ttl_seconds=60)
    assert a != b
    assert len(a) > 16 and len(b) > 16


# --- grant store: in-memory ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_single_use_grant_is_redeemed_exactly_once():
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)

    first = await store.check_and_consume(digest="d1", subject="key:agent1")
    second = await store.check_and_consume(digest="d1", subject="key:agent1")

    assert first.ok is True
    assert (second.ok, second.reason) == (False, "consumed")


@pytest.mark.asyncio
async def test_a_repeatable_grant_survives_unlimited_redemption_by_the_same_subject():
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=True, ttl_seconds=60)

    results = [await store.check_and_consume(digest="d1", subject="key:agent1") for _ in range(5)]

    assert all(r.ok for r in results)


@pytest.mark.asyncio
async def test_no_grant_at_all_is_not_found():
    store = InMemoryWritePlannedGrantStore()
    result = await store.check_and_consume(digest="never-issued", subject="key:agent1")
    assert (result.ok, result.reason, result.grant) == (False, "not_found", None)


@pytest.mark.asyncio
async def test_an_expired_grant_is_refused_as_expired_not_not_found():
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=-1)
    result = await store.check_and_consume(digest="d1", subject="key:agent1")
    assert result.reason == "expired"


@pytest.mark.asyncio
async def test_a_grant_is_refused_for_any_subject_other_than_the_proposer():
    """The whole security property: Review binds the grant to whoever *proposed* it, and
    Apply must be that same caller — not the reviewer, not anyone else holding baseline
    scope."""
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)

    result = await store.check_and_consume(digest="d1", subject="key:agent2")

    assert (result.ok, result.reason) == (False, "subject_mismatch")


@pytest.mark.asyncio
async def test_a_reviewer_subject_holding_the_review_scope_still_cannot_redeem_it():
    """Explicitly: holding `devices:write` (the scope that lets you approve) confers no
    ability to redeem the grant you just minted for someone else."""
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)

    result = await store.check_and_consume(digest="d1", subject="key:op1")

    assert (result.ok, result.reason) == (False, "subject_mismatch")


@pytest.mark.asyncio
async def test_re_approving_the_same_digest_replaces_the_prior_grant():
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)
    await store.check_and_consume(digest="d1", subject="key:agent1")  # spend it

    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op2", repeatable=False, ttl_seconds=60)
    fresh = await store.check_and_consume(digest="d1", subject="key:agent1")

    assert fresh.ok is True, "a fresh approval must not inherit the old grant's spent state"


@pytest.mark.asyncio
async def test_concurrent_redemption_of_a_single_use_grant_has_exactly_one_winner():
    """The property the whole atomic-consume design exists for. In-process this only proves
    no `await` point can interleave inside the check — the real concurrency proof, against
    Redis `HSETNX`, is below."""
    store = InMemoryWritePlannedGrantStore()
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)

    results = await asyncio.gather(*[store.check_and_consume(digest="d1", subject="key:agent1") for _ in range(20)])

    assert sum(1 for r in results if r.ok) == 1


# --- the Redis stores, against real Redis -------------------------------------------------
#
# Same reasoning as test_break_glass_activity.py's own Redis section: the atomicity claim
# rests on a real HSETNX race and a real TTL actually expiring, which fakeredis cannot stand
# in for credibly — assert against the real server or skip, never stub.


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_proposal_store_round_trips_a_nested_plan(real_redis):
    store = RedisPendingProposalStore(real_redis)
    nested_plan = {**PLAN, "auth": {"auth_type": "oauth2", "scopes": ["a", "b"]}}
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=nested_plan, ttl_seconds=60)

    proposal = await store.get(proposal_id)

    assert proposal is not None
    assert proposal.plan == nested_plan
    assert proposal.degraded is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_proposal_store_deletes_for_real(real_redis):
    store = RedisPendingProposalStore(real_redis)
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=60)
    await store.delete(proposal_id)
    assert await store.get(proposal_id) is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_proposal_ttl_really_expires(real_redis):
    store = RedisPendingProposalStore(real_redis)
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=1)
    assert await store.get(proposal_id) is not None

    await asyncio.sleep(1.3)

    assert await store.get(proposal_id) is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_grant_store_concurrent_redemption_has_exactly_one_winner(real_redis):
    """The proof the whole design rests on: `HSETNX`'s atomicity, not asyncio's — a
    single-use grant redeemed by 20 concurrent Applies must be consumed exactly once, even
    though every one of them reads the same pre-consumption state before racing to write."""
    store = RedisWritePlannedGrantStore(real_redis)
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)

    results = await asyncio.gather(*[store.check_and_consume(digest="d1", subject="key:agent1") for _ in range(20)])

    winners = [r for r in results if r.ok]
    losers = [r for r in results if not r.ok]
    assert len(winners) == 1
    assert all(r.reason == "consumed" for r in losers)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_repeatable_grant_survives_concurrent_redemption_by_all(real_redis):
    store = RedisWritePlannedGrantStore(real_redis)
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=True, ttl_seconds=60)

    results = await asyncio.gather(*[store.check_and_consume(digest="d1", subject="key:agent1") for _ in range(20)])

    assert all(r.ok for r in results)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_grant_ttl_really_expires(real_redis):
    store = RedisWritePlannedGrantStore(real_redis)
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=1)
    assert (await store.check_and_consume(digest="d1", subject="key:agent1")).ok is True

    await store.issue(digest="d2", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=1)
    await asyncio.sleep(1.3)

    result = await store.check_and_consume(digest="d2", subject="key:agent1")
    assert result.reason in ("expired", "not_found"), "Redis may have already reaped the key via its own TTL"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redis_re_approval_replaces_the_prior_grant(real_redis):
    store = RedisWritePlannedGrantStore(real_redis)
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)
    await store.check_and_consume(digest="d1", subject="key:agent1")

    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op2", repeatable=False, ttl_seconds=60)
    fresh = await store.check_and_consume(digest="d1", subject="key:agent1")

    assert fresh.ok is True


# --- the Redis stores degrade rather than fail the caller -----------------------------------


class _DeadRedis:
    def pipeline(self, transaction=True):
        raise ConnectionError("redis is gone")

    async def hgetall(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def delete(self, *a, **kw):
        raise ConnectionError("redis is gone")

    async def hsetnx(self, *a, **kw):
        raise ConnectionError("redis is gone")


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_the_proposal_store_rather_than_raising():
    store = RedisPendingProposalStore(_DeadRedis())
    proposal_id = await store.create(subject="key:agent1", digest="d1", plan=PLAN, ttl_seconds=60)  # must not raise

    proposal = await store.get(proposal_id)

    assert proposal is not None
    assert proposal.degraded is True


@pytest.mark.asyncio
async def test_a_dead_redis_degrades_the_grant_store_rather_than_raising():
    store = RedisWritePlannedGrantStore(_DeadRedis())
    grant = await store.issue(
        digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60
    )
    assert grant.degraded is True

    result = await store.check_and_consume(digest="d1", subject="key:agent1")

    assert result.ok is True
    assert result.degraded is True


@pytest.mark.asyncio
async def test_a_degraded_single_use_grant_is_still_consumed_exactly_once_within_the_process():
    """The fallback's guarantee is process-local, not cluster-wide — but within the one
    process that is degraded, single-use must still mean single-use."""
    store = RedisWritePlannedGrantStore(_DeadRedis())
    await store.issue(digest="d1", subject="key:agent1", reviewer_subject="key:op1", repeatable=False, ttl_seconds=60)

    first = await store.check_and_consume(digest="d1", subject="key:agent1")
    second = await store.check_and_consume(digest="d1", subject="key:agent1")

    assert (first.ok, second.ok, second.reason) == (True, False, "consumed")


# --- the app.state lazy-fallback getters -----------------------------------------------------


def test_pending_proposal_store_creates_and_keeps_one_when_nothing_was_wired():
    from types import SimpleNamespace

    state = SimpleNamespace()
    store = pending_proposal_store(state)
    assert isinstance(store, InMemoryPendingProposalStore)
    assert pending_proposal_store(state) is store, "created once, reused after"


def test_write_planned_grant_store_creates_and_keeps_one_when_nothing_was_wired():
    from types import SimpleNamespace

    state = SimpleNamespace()
    store = write_planned_grant_store(state)
    assert isinstance(store, InMemoryWritePlannedGrantStore)
    assert write_planned_grant_store(state) is store, "created once, reused after"


def test_lazy_getters_survive_a_state_object_that_refuses_new_attributes():
    class _Frozen:
        __slots__ = ()

    frozen = _Frozen()
    store = pending_proposal_store(frozen)  # must not raise
    assert isinstance(store, InMemoryPendingProposalStore)
