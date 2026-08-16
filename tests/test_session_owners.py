# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Embedded mode's session→owner map expires (the distributed one always did).

Found while wiring the console's tool-invocation route, which opens a session per
operation. Distributed mode was already safe: `SessionRouter` pipelines `hset` with
`expire`, so an abandoned session costs one key for at most a day. Embedded mode kept the
same fact in a plain dict that only ever shrank on an explicit DELETE — so a crash, a
timeout or a redeploy between `initialize` and teardown leaked an entry for the life of the
process.

The same shape as the two dangling-lease bugs already shipped here: the cleanup path exists,
is correct, and is not the one taken when something goes wrong.
"""

from __future__ import annotations

import pytest

from device_mcp_gateway.shared.session_owners import ExpiringOwners
from device_mcp_gateway.shared.session_router import SESSION_TTL


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_an_abandoned_session_does_not_outlive_its_ttl():
    """The leak, stated directly. No DELETE ever arrives — the BFF died mid-sequence."""
    clock = _Clock()
    owners = ExpiringOwners(ttl=60, clock=clock)
    owners["s-1"] = "oidc:iss#alice"
    assert owners.get("s-1") == "oidc:iss#alice"

    clock.now += 61
    assert owners.get("s-1") is None
    assert len(owners) == 0


def test_a_live_session_is_not_dropped_early():
    """The control. Without it, "expire everything immediately" passes the test above and
    breaks every MCP client, since a session id that stops resolving is a 404 mid-stream."""
    clock = _Clock()
    owners = ExpiringOwners(ttl=60, clock=clock)
    owners["s-1"] = "oidc:iss#alice"
    clock.now += 59
    assert owners.get("s-1") == "oidc:iss#alice"


def test_expired_entries_are_reclaimed_rather_than_merely_hidden():
    """Hiding an expired entry on read would still leak memory, which is the actual defect —
    the owner lookup already behaved correctly, the storage did not."""
    clock = _Clock()
    owners = ExpiringOwners(ttl=60, clock=clock)
    for i in range(50):
        owners[f"s-{i}"] = "someone"
    clock.now += 61
    owners["s-new"] = "someone-else"
    assert len(owners._entries) == 1


def test_a_session_that_is_deleted_is_gone_immediately():
    """Explicit teardown still works and does not wait for the TTL — the common path must
    not become the slow one just because the uncommon one got a backstop."""
    owners = ExpiringOwners(ttl=60, clock=_Clock())
    owners["s-1"] = "alice"
    owners.pop("s-1", None)
    assert owners.get("s-1") is None
    assert owners.pop("s-1", None) is None  # popping twice is what a double DELETE does


def test_reading_an_expired_session_raises_like_a_missing_one():
    """`__getitem__` is what a `[...]` lookup in the fleet routes uses. An expired session
    must be indistinguishable from an unknown one, or those routes would serve a stale
    owner rather than telling the client to re-initialize."""
    clock = _Clock()
    owners = ExpiringOwners(ttl=60, clock=clock)
    owners["s-1"] = "alice"
    clock.now += 61
    with pytest.raises(KeyError):
        owners["s-1"]


def test_the_two_modes_agree_on_how_long_an_abandoned_session_lives():
    """Asserted rather than commented: the embedded default is *the* distributed constant,
    so the two cannot drift into different definitions of an abandoned session."""
    assert ExpiringOwners()._ttl == SESSION_TTL


def test_it_is_still_a_mapping_the_routes_can_use():
    """The routes treat this as a dict — `get`, item assignment, `pop`. Pinned so a future
    change to the storage cannot quietly drop one of the three."""
    owners = ExpiringOwners(ttl=60, clock=_Clock())
    owners["s-1"] = "alice"
    assert "s-1" in owners and list(owners) == ["s-1"]
    assert owners.get("s-1") == "alice"
    assert owners.pop("s-1") == "alice"
