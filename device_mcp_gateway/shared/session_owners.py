# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Embedded mode's MCP session → owner map, bounded the way the distributed one is.

Distributed mode keeps this in Redis through :class:`SessionRouter`, where every key is
written with a TTL in the same pipeline as the hash — so an abandoned session costs one key
for at most a day. Embedded mode kept the same fact in a plain ``dict``: written on
``initialize``, removed only on an explicit ``DELETE``, and reclaimed by nothing.

That was invisible while the only MCP clients were long-lived agents that tear their own
sessions down. It stops being invisible the moment a caller opens a session per operation —
the console's tool-invocation route runs `initialize` → `tools/call` → `DELETE`, and any
crash, timeout or redeploy between the first and last leaves an entry that never goes away.
The gap is the same shape as the two dangling-lease bugs this project has already shipped:
a cleanup path that exists, is correct, and is not the one taken when something goes wrong.

The TTL is deliberately the *same constant* the distributed side uses, so the two modes
cannot drift into different definitions of how long an abandoned session lives.
"""

from __future__ import annotations

import time
from typing import Iterator, MutableMapping, Optional

from device_mcp_gateway.shared.session_router import SESSION_TTL


class ExpiringOwners(MutableMapping[str, str]):
    """A ``{session_id: owner}`` map whose entries expire.

    Expiry is checked on read and swept on write. A sweep per write is O(n) in the number of
    live sessions, which in embedded mode — one process, one operator's console — is small,
    and writes happen once per session rather than once per message. Doing it on a timer
    instead would add a task to cancel on shutdown for no measurable gain.
    """

    def __init__(self, ttl: int = SESSION_TTL, *, clock=time.monotonic) -> None:
        self._ttl = ttl
        self._clock = clock
        self._entries: dict[str, tuple[str, float]] = {}

    def _sweep(self, now: float) -> None:
        for sid in [s for s, (_, exp) in self._entries.items() if exp <= now]:
            del self._entries[sid]

    def __setitem__(self, session_id: str, owner: str) -> None:
        now = self._clock()
        self._sweep(now)
        self._entries[session_id] = (owner, now + self._ttl)

    def __getitem__(self, session_id: str) -> str:
        owner, exp = self._entries[session_id]
        if exp <= self._clock():
            # Removed rather than merely hidden: a caller that reads an expired session and
            # then writes a different one should not still be paying for this entry.
            del self._entries[session_id]
            raise KeyError(session_id)
        return owner

    def __delitem__(self, session_id: str) -> None:
        del self._entries[session_id]

    def __iter__(self) -> Iterator[str]:
        now = self._clock()
        return iter([s for s, (_, exp) in self._entries.items() if exp > now])

    def __len__(self) -> int:
        now = self._clock()
        return sum(1 for _, exp in self._entries.values() if exp > now)

    def get(self, session_id: str, default: Optional[str] = None) -> Optional[str]:  # type: ignore[override]
        try:
            return self[session_id]
        except KeyError:
            return default
