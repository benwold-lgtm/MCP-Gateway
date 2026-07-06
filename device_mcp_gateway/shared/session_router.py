# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
SSE session registry and result routing via a durable per-session Redis Stream.

In distributed mode every gateway instance is stateless with respect to
SSE clients.  When a client opens a stream on Gateway A and a tool call
arrives at Gateway B, the result still reaches the client because:

  Worker → XADD session:{id}:results <json-rpc-response>
         → Redis Stream (durable, buffered)
         → Gateway A (XREAD BLOCK on session:{id}:results) → SSE event

A Stream rather than pub/sub (SRE #3): pub/sub is fire-and-forget, so a result
published while the single subscribing gateway was mid-restart, briefly
disconnected, or between reads was lost — and because the worker had already
marked the call handled, the F6 timeout watcher stood down too, leaving the
client to hang. A Stream buffers undelivered entries and lets the reader start
from id "0", so results that arrive between register() and subscribe() are not
missed. The stream is bounded (MAXLEN) and carries the session TTL so abandoned
sessions can't leak.

Session keys carry a TTL so abandoned sessions expire automatically.
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncGenerator

from loguru import logger

_SESSION_TTL = 86_400  # 24 h — refreshed periodically while the stream is active
_REFRESH_THROTTLE = 60.0  # min seconds between TTL refreshes on a busy stream
# Cap a session's buffered results so a client that stops reading can't grow the
# stream without bound. Approximate trimming keeps XADD O(1).
_RESULTS_MAXLEN = 1000
# Block this long on each XREAD before looping. Short enough that client
# disconnect (task cancellation) and shutdown are observed promptly; long enough
# to avoid a busy spin. sse-starlette sends its own keep-alive pings meanwhile.
_XREAD_BLOCK_MS = 5_000


def _results_key(session_id: str) -> str:
    return f"session:{session_id}:results"


def _fleet_tools_key(session_id: str) -> str:
    return f"fleet:{session_id}:tools"


def _field(fields: dict, name: str) -> str | None:
    """Read a stream-entry field tolerant of str or bytes keys/values.

    Real Redis with decode_responses=True yields str keys/values; fakeredis does
    not decode stream fields, so the same entry comes back with bytes keys. Accept
    both so the unit suite (fakeredis) and production (real Redis) agree.
    """
    val = fields.get(name)
    if val is None:
        val = fields.get(name.encode())
    if isinstance(val, bytes):
        val = val.decode()
    return val


def _decode(val: Any) -> str:
    return val.decode() if isinstance(val, bytes) else val


class _RefreshThrottle:
    """Permits an action at most once per `window` seconds (monotonic clock).

    Used to cap session-TTL refreshes: a busy SSE stream would otherwise issue
    one Redis EXPIRE per message. One refresh per minute keeps a 24 h TTL alive
    with negligible Redis traffic.
    """

    def __init__(self, window: float) -> None:
        self._window = window
        self._last = 0.0  # 0 → first call always fires

    def ready(self, now: float) -> bool:
        if now - self._last >= self._window:
            self._last = now
            return True
        return False


class SessionRouter:
    """Register SSE sessions and route results across gateway instances."""

    def __init__(self, redis_client: Any, pubsub_client: Any = None) -> None:
        self._r = redis_client
        # Long-lived SSE subscriptions each hold a connection for their whole
        # lifetime. Route them through a dedicated client/pool so they don't
        # exhaust the shared command pool (F3). Falls back to the command client
        # when no separate one is supplied.
        self._ps = pubsub_client if pubsub_client is not None else redis_client

    async def register(
        self,
        session_id: str,
        hostname: str,
        gateway_id: str,
        ttl: int = _SESSION_TTL,
        owner: str | None = None,
    ) -> None:
        """Record that session_id is held by this gateway instance.

        ``owner`` is the principal subject that opened the session; it binds the
        session to that principal so another caller can't post to it (F-37).
        """
        key = f"session:{session_id}"
        mapping = {"hostname": hostname, "gateway_id": gateway_id}
        if owner is not None:
            mapping["owner"] = owner
        # Pipeline hset + expire so the hash never lands without a TTL — a drop
        # between two separate round-trips would otherwise leak the session key.
        pipe = self._r.pipeline()
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, ttl)
        await pipe.execute()
        logger.debug(f"Session registered: session_id={session_id} gateway={gateway_id}")

    async def get(self, session_id: str) -> dict | None:
        h = await self._r.hgetall(f"session:{session_id}")
        if not h:
            return None
        # Decode defensively: real Redis with decode_responses=True already returns
        # str, so this is a no-op there. Some test doubles (fakeredis) don't honour
        # decode_responses for hash fields, returning bytes -- silently breaking any
        # str comparison against the result, including the F-37 owner-mismatch
        # check callers run on the "owner" field.
        return {_decode(k): _decode(v) for k, v in h.items()}

    async def refresh(self, session_id: str, ttl: int = _SESSION_TTL) -> None:
        # Keep the session hash, its results stream, and (for a fleet session) its
        # tools lookup table on the same TTL so none outlives the others. EXPIRE
        # on a key that doesn't exist (e.g. fleet_tools for a per-device session)
        # is a harmless no-op.
        pipe = self._r.pipeline()
        pipe.expire(f"session:{session_id}", ttl)
        pipe.expire(_results_key(session_id), ttl)
        pipe.expire(_fleet_tools_key(session_id), ttl)
        await pipe.execute()

    async def delete(self, session_id: str) -> None:
        pipe = self._r.pipeline()
        pipe.delete(f"session:{session_id}")
        pipe.delete(_results_key(session_id))
        pipe.delete(_fleet_tools_key(session_id))
        await pipe.execute()
        logger.debug(f"Session deleted: session_id={session_id}")

    async def set_fleet_tools(self, session_id: str, tools: dict[str, dict], ttl: int = _SESSION_TTL) -> None:
        """Persist a fleet session's display-name -> tool-entry lookup table.

        Each entry carries ``hostname``/``real_name`` (for ``tools/call`` dispatch)
        plus ``description``/``schema`` (so ``tools/list`` can be re-served by
        whichever gateway replica receives it, without re-querying every device).
        A POST may land on a different replica than the GET that opened the
        session, so this must be in Redis rather than in-process memory.
        """
        if not tools:
            return
        key = _fleet_tools_key(session_id)
        mapping = {name: json.dumps(entry) for name, entry in tools.items()}
        pipe = self._r.pipeline()
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, ttl)
        await pipe.execute()

    async def get_fleet_tools(self, session_id: str) -> dict[str, dict] | None:
        h = await self._r.hgetall(_fleet_tools_key(session_id))
        if not h:
            return None
        return {_decode(k): json.loads(_decode(v)) for k, v in h.items()}

    async def subscribe(self, session_id: str) -> AsyncGenerator[dict, None]:
        """Yield JSON-RPC response dicts from this session's durable results stream.

        Reads via XREAD BLOCK on a dedicated connection (so the command client
        stays free) starting from id "0", so results buffered between register()
        and this call are not missed. Exits when the generator is cancelled
        (client disconnect).
        """
        key = _results_key(session_id)
        last_id = "0"  # read from the start so nothing buffered pre-subscribe is lost
        throttle = _RefreshThrottle(_REFRESH_THROTTLE)
        logger.debug(f"Reading results stream {key}")
        try:
            while True:
                resp = await self._ps.xread({key: last_id}, count=10, block=_XREAD_BLOCK_MS)
                if not resp:
                    continue  # block elapsed with no new entries — loop (allows cancellation)
                # Throttle TTL refreshes so a busy stream doesn't issue one EXPIRE
                # per message (RC-3).
                if throttle.ready(time.monotonic()):
                    await self.refresh(session_id)
                for _stream, entries in resp:
                    for msg_id, fields in entries:
                        last_id = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                        raw = _field(fields, "data")
                        if raw is None:
                            logger.warning(f"Results entry on {key} missing 'data' field: {fields!r}")
                            continue
                        try:
                            yield json.loads(raw)
                        except json.JSONDecodeError:
                            logger.warning(f"Non-JSON entry on {key}: {raw!r}")
        finally:
            logger.debug(f"Stopped reading results stream {key}")

    async def publish_result(self, session_id: str, result: dict) -> None:
        """Append a JSON-RPC result to the session's durable results stream.

        XADD + EXPIRE in one pipeline so the stream is bounded in size (MAXLEN)
        and lifetime (TTL) regardless of whether a gateway ever drains it.
        """
        key = _results_key(session_id)
        pipe = self._r.pipeline()
        pipe.xadd(key, {"data": json.dumps(result)}, maxlen=_RESULTS_MAXLEN, approximate=True)
        pipe.expire(key, _SESSION_TTL)
        await pipe.execute()
