# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Registry backend abstraction.

DeviceConfig — serialisable device record (no asyncio types, no pod references).
AbstractRegistryBackend — interface for all registry state operations.
MemoryRegistryBackend  — in-process dict; used by registry.mode = "embedded".
RedisRegistryBackend   — Redis-backed; used by registry.mode = "distributed".
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from loguru import logger

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class DeviceConfig:
    """Serialisable device record stored in the shared registry.

    All fields are plain Python types so the record can be round-tripped
    through JSON / Redis Hashes without pickling.  Runtime-only state
    (pod object, asyncio locks, local queues) is kept in the Worker, not here.
    """

    hostname: str
    base_url: str
    transport: str = "sse"
    spec_url: str | None = None
    auth_type: str | None = None
    auth_config: str | None = None  # Fernet-encrypted JSON string
    rate_limit_rps: float | None = None
    spec_hash: str | None = None
    pod_active: bool = False
    reachable: bool = True
    last_check: float = field(default_factory=time.time)
    spawn_error: str | None = None
    worker_id: str | None = None
    # Monotonic counter bumped whenever a spec change mutated the generated tool
    # set (F-41). A client polls this to detect "the tools moved under me" and
    # re-list; the audit stream records what changed and whether it was breaking.
    tools_revision: int = 0

    # --- serialisation helpers ---

    def to_redis_hash(self) -> dict[str, str]:
        """Encode all fields as Redis Hash (str → str) for HSET."""
        d = asdict(self)
        return {k: "" if v is None else str(v) for k, v in d.items()}

    @classmethod
    def from_redis_hash(cls, h: dict[str, str]) -> "DeviceConfig":
        """Reconstruct from a Redis Hash returned by HGETALL."""

        def _opt_float(v: str) -> float | None:
            return float(v) if v else None

        def _opt_str(v: str) -> str | None:
            return v if v else None

        return cls(
            hostname=h["hostname"],
            base_url=h["base_url"],
            transport=h.get("transport", "sse"),
            spec_url=_opt_str(h.get("spec_url", "")),
            auth_type=_opt_str(h.get("auth_type", "")),
            auth_config=_opt_str(h.get("auth_config", "")),
            rate_limit_rps=_opt_float(h.get("rate_limit_rps", "")),
            spec_hash=_opt_str(h.get("spec_hash", "")),
            pod_active=h.get("pod_active", "False") == "True",
            reachable=h.get("reachable", "True") == "True",
            last_check=float(h.get("last_check", "0") or "0"),
            spawn_error=_opt_str(h.get("spawn_error", "")),
            worker_id=_opt_str(h.get("worker_id", "")),
            tools_revision=int(h.get("tools_revision", "0") or "0"),
        )


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class AbstractRegistryBackend(ABC):
    """All registry state operations — device configs, manifests, and streams."""

    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def get_device(self, hostname: str) -> DeviceConfig | None: ...

    @abstractmethod
    async def set_device(self, hostname: str, config: DeviceConfig) -> None: ...

    @abstractmethod
    async def update_device_fields(self, hostname: str, **fields: Any) -> None:
        """Partial update — only write the supplied fields."""
        ...

    @abstractmethod
    async def delete_device(self, hostname: str) -> None: ...

    @abstractmethod
    async def list_hostnames(self) -> list[str]: ...

    async def get_devices(self, hostnames: list[str]) -> list[DeviceConfig]:
        """Fetch many device configs. Default: one get_device per hostname.

        Backends with a multi-key fetch (e.g. Redis pipelines) should override
        this to avoid N round-trips.
        """
        out: list[DeviceConfig] = []
        for h in hostnames:
            cfg = await self.get_device(h)
            if cfg:
                out.append(cfg)
        return out

    @abstractmethod
    async def get_manifest(self, hostname: str) -> dict | None: ...

    @abstractmethod
    async def set_manifest(self, hostname: str, manifest: dict, ttl: int) -> None: ...

    @abstractmethod
    async def delete_manifest(self, hostname: str) -> None: ...

    @abstractmethod
    async def publish_assignment(self, action: str, hostname: str) -> None:
        """Publish an assign/unassign event for workers to consume."""
        ...

    @abstractmethod
    async def publish_tool_call(
        self,
        hostname: str,
        request_id: str,
        session_id: str,
        gateway_id: str,
        message: dict,
        rid: str = "",
        traceparent: str = "",
        subject: str = "",
    ) -> None:
        """Push a tool-call message onto the device's Redis Stream.

        `rid` is the gateway's X-Request-Id correlation id; it rides along on the
        stream so the worker can bind it in its audit log, giving one trace id
        across the gateway→worker hop (SRE O2). `traceparent` is the optional W3C
        trace-context (F-14): when tracing is on, the worker starts its execution
        span as a child of it so the call is one end-to-end trace. `subject` is
        the authenticated principal that issued the call (F-30 residual): it
        rides the stream so the worker's execution-audit record carries the same
        actor attribution the gateway logged at dispatch, extending the audit
        trail past the gateway edge.
        """
        ...

    async def call_backlog(self, hostname: str) -> int:
        """Undelivered tool-calls queued for ``hostname`` (admission signal, F-06).

        Default 0: backends that route calls in-process (embedded mode) have no
        queue to back up, so they never shed. The Redis backend overrides this
        with the consumer-group lag.
        """
        return 0

    # --- Dead-letter queue operations (F-10) ---------------------------------
    # Default no-ops: embedded mode routes in-process and has no DLQ. The Redis
    # backend overrides these for the distributed-mode device:{h}:calls:dead stream.

    async def dead_letter_list(self, hostname: str, count: int = 50) -> list[dict]:
        """Return up to ``count`` dead-lettered calls (newest first), parsed for display."""
        return []

    async def dead_letter_replay(self, hostname: str, ids: list[str] | None = None, count: int = 50) -> int:
        """Re-publish dead-lettered calls onto the device's call stream and remove
        them from the DLQ. ``ids`` selects specific entries; otherwise up to
        ``count`` oldest are replayed. Returns the number replayed."""
        return 0

    async def dead_letter_purge(self, hostname: str, ids: list[str] | None = None) -> int:
        """Delete dead-lettered calls — ``ids`` for specific entries, else the whole
        DLQ. Returns the number removed (or -1 when the whole stream was dropped)."""
        return 0


# ---------------------------------------------------------------------------
# In-memory backend (embedded mode)
# ---------------------------------------------------------------------------


class MemoryRegistryBackend(AbstractRegistryBackend):
    """Dict-backed backend for registry.mode = 'embedded'.

    Publish methods are no-ops because the Registry drives pod lifecycle
    directly when running in embedded mode.
    """

    def __init__(self) -> None:
        self._devices: dict[str, DeviceConfig] = {}
        self._manifests: dict[str, dict] = {}

    async def initialize(self) -> None:
        pass

    async def get_device(self, hostname: str) -> DeviceConfig | None:
        return self._devices.get(hostname)

    async def set_device(self, hostname: str, config: DeviceConfig) -> None:
        self._devices[hostname] = config

    async def update_device_fields(self, hostname: str, **fields: Any) -> None:
        cfg = self._devices.get(hostname)
        if cfg:
            for k, v in fields.items():
                setattr(cfg, k, v)

    async def delete_device(self, hostname: str) -> None:
        self._devices.pop(hostname, None)

    async def list_hostnames(self) -> list[str]:
        return list(self._devices.keys())

    async def get_manifest(self, hostname: str) -> dict | None:
        return self._manifests.get(hostname)

    async def set_manifest(self, hostname: str, manifest: dict, ttl: int) -> None:
        self._manifests[hostname] = manifest

    async def delete_manifest(self, hostname: str) -> None:
        self._manifests.pop(hostname, None)

    async def publish_assignment(self, action: str, hostname: str) -> None:
        pass  # no-op; embedded Registry drives pod lifecycle directly

    async def publish_tool_call(
        self,
        hostname: str,
        request_id: str,
        session_id: str,
        gateway_id: str,
        message: dict,
        rid: str = "",
        traceparent: str = "",
        subject: str = "",
    ) -> None:
        pass  # no-op; embedded mode routes calls in-process


# ---------------------------------------------------------------------------
# Redis backend (distributed mode)
# ---------------------------------------------------------------------------

_DEVICES_SET = "devices:all"
_ASSIGNMENTS_STREAM = "device:assignments"
_WORKER_GROUP = "workers"
# Unassign is delivered on a SEPARATE stream that every worker tails independently
# (broadcast), not via the shared competing-consumers group. An "assign" only needs
# one worker to act, but an "unassign" must reach whichever worker actually owns the
# pod — and on the shared group it landed on one arbitrary worker that usually wasn't
# the owner, so the pod was never torn down and a PUT-replace never applied its new
# config. Bounded so a churny fleet can't grow it without limit.
_UNASSIGN_STREAM = "device:unassignments"
_UNASSIGN_STREAM_MAXLEN = 10_000
# Cap a device's pending tool-call stream so a backlog (slow/crashed worker, no
# consumer) can't grow Redis without bound (SRE #4). Approximate trimming keeps
# XADD O(1); the real backpressure is the worker's per-device concurrency cap.
_CALL_STREAM_MAXLEN = 10_000


class RedisRegistryBackend(AbstractRegistryBackend):
    """Redis-backed backend for registry.mode = 'distributed'.

    Key layout:
      devices:all                  → Set of hostnames
      device:{hostname}:config     → Hash (DeviceConfig fields)
      device:{hostname}:manifest   → String (JSON, with TTL)
      device:assignments           → Stream {action, hostname}
      device:{hostname}:calls      → Stream {request_id, session_id, gateway_id, message}
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client

    async def initialize(self) -> None:
        # Ensure consumer group exists for the assignments stream.
        try:
            await self._r.xgroup_create(_ASSIGNMENTS_STREAM, _WORKER_GROUP, id="0", mkstream=True)
            logger.info("Created Redis consumer group 'workers' on device:assignments")
        except Exception as exc:
            if "BUSYGROUP" in str(exc):
                pass  # group already exists — normal on restart
            else:
                logger.warning(f"xgroup_create warning: {exc}")

    async def get_device(self, hostname: str) -> DeviceConfig | None:
        h = await self._r.hgetall(f"device:{hostname}:config")
        if not h:
            return None
        return DeviceConfig.from_redis_hash(h)

    async def get_devices(self, hostnames: list[str]) -> list[DeviceConfig]:
        """Fetch all device configs in a single pipeline (avoids N round-trips)."""
        if not hostnames:
            return []
        pipe = self._r.pipeline()
        for h in hostnames:
            pipe.hgetall(f"device:{h}:config")
        raw_hashes = await pipe.execute()
        return [DeviceConfig.from_redis_hash(h) for h in raw_hashes if h]

    async def set_device(self, hostname: str, config: DeviceConfig) -> None:
        pipe = self._r.pipeline()
        pipe.hset(f"device:{hostname}:config", mapping=config.to_redis_hash())
        pipe.sadd(_DEVICES_SET, hostname)
        await pipe.execute()

    async def update_device_fields(self, hostname: str, **fields: Any) -> None:
        mapping = {k: "" if v is None else str(v) for k, v in fields.items()}
        await self._r.hset(f"device:{hostname}:config", mapping=mapping)

    async def delete_device(self, hostname: str) -> None:
        pipe = self._r.pipeline()
        pipe.delete(f"device:{hostname}:config")
        pipe.delete(f"device:{hostname}:manifest")
        # Drop the tool-call stream and its dead-letter stream too, or they linger
        # in Redis after the device is gone and accumulate over churn (RC-4, SRE #4).
        pipe.delete(f"device:{hostname}:calls")
        pipe.delete(f"device:{hostname}:calls:dead")
        pipe.srem(_DEVICES_SET, hostname)
        await pipe.execute()

    async def list_hostnames(self) -> list[str]:
        return list(await self._r.smembers(_DEVICES_SET))

    async def get_manifest(self, hostname: str) -> dict | None:
        raw = await self._r.get(f"device:{hostname}:manifest")
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set_manifest(self, hostname: str, manifest: dict, ttl: int) -> None:
        await self._r.set(f"device:{hostname}:manifest", json.dumps(manifest), ex=ttl)

    async def delete_manifest(self, hostname: str) -> None:
        await self._r.delete(f"device:{hostname}:manifest")

    async def publish_assignment(self, action: str, hostname: str) -> None:
        if action == "unassign":
            # Broadcast: every worker tails this stream so the actual owner tears down
            # its pod (non-owners no-op). See _UNASSIGN_STREAM rationale above.
            await self._r.xadd(
                _UNASSIGN_STREAM, {"hostname": hostname}, maxlen=_UNASSIGN_STREAM_MAXLEN, approximate=True
            )
        else:
            await self._r.xadd(_ASSIGNMENTS_STREAM, {"action": action, "hostname": hostname})
        logger.debug(f"Published assignment: action={action} hostname={hostname}")

    async def publish_tool_call(
        self,
        hostname: str,
        request_id: str,
        session_id: str,
        gateway_id: str,
        message: dict,
        rid: str = "",
        traceparent: str = "",
        subject: str = "",
    ) -> None:
        await self._r.xadd(
            f"device:{hostname}:calls",
            {
                "request_id": request_id,
                "session_id": session_id,
                "gateway_id": gateway_id,
                "rid": rid,
                "traceparent": traceparent,
                "subject": subject,
                "message": json.dumps(message),
            },
            maxlen=_CALL_STREAM_MAXLEN,
            approximate=True,
        )

    async def call_backlog(self, hostname: str) -> int:
        """Entries XADDed to the device's call stream but not yet delivered to
        the worker consumer group (XINFO GROUPS ``lag``) — the admission-control
        signal for F-06.

        A growing lag means the worker isn't draining the stream; once it nears
        ``_CALL_STREAM_MAXLEN`` the oldest undelivered calls are silently trimmed
        on the next XADD. The gateway reads this before publishing and fast-fails
        (429) past a watermark, turning a silent drop into a visible reject.

        Returns 0 when the stream/group doesn't exist yet (nothing queued) or on
        any Redis error, so a metrics hiccup never wrongly sheds live traffic.
        """
        group = f"workers-{hostname}"
        try:
            groups = await self._r.xinfo_groups(f"device:{hostname}:calls")
        except Exception:
            return 0
        for g in groups:
            if not isinstance(g, dict):
                continue
            name = g.get("name")
            if isinstance(name, bytes):
                name = name.decode()
            if name == group:
                lag = g.get("lag")
                try:
                    return int(lag) if lag is not None else 0
                except (TypeError, ValueError):
                    return 0
        return 0

    # --- Dead-letter queue operations (F-10) ---------------------------------

    @staticmethod
    def _decode_entry(fields: Any) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in (fields or {}).items():
            kk = k.decode() if isinstance(k, bytes) else k
            vv = v.decode() if isinstance(v, bytes) else v
            out[kk] = vv
        return out

    async def dead_letter_list(self, hostname: str, count: int = 50) -> list[dict]:
        key = f"device:{hostname}:calls:dead"
        try:
            entries = await self._r.xrevrange(key, count=count)  # newest first
        except Exception:
            return []
        result: list[dict] = []
        for entry_id, fields in entries:
            f = self._decode_entry(fields)
            eid = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
            # Parse the JSON-RPC method out of the carried message for at-a-glance triage.
            method = None
            try:
                msg = json.loads(f.get("message", "{}"))
                method = msg.get("method") if isinstance(msg, dict) else None
            except (json.JSONDecodeError, TypeError):
                method = None
            result.append(
                {
                    "id": eid,
                    "reason": f.get("reason", ""),
                    "ts": f.get("ts", ""),
                    "method": method,
                    "rid": f.get("rid", ""),
                    "request_id": f.get("request_id", ""),
                    "session_id": f.get("session_id", ""),
                }
            )
        return result

    async def dead_letter_replay(self, hostname: str, ids: list[str] | None = None, count: int = 50) -> int:
        """Re-publish DLQ entries onto the live call stream, then XDEL them.

        Replay keeps the original request_id/session_id/rid/traceparent so logs and
        any still-live session correlate; the DLQ-only ``reason``/``ts`` are dropped.
        A result for an expired session is best-effort — the call still re-executes.
        """
        dead_key = f"device:{hostname}:calls:dead"
        calls_key = f"device:{hostname}:calls"
        try:
            if ids:
                entries = []
                for i in ids:
                    entries.extend(await self._r.xrange(dead_key, min=i, max=i))
            else:
                entries = await self._r.xrange(dead_key, count=count)  # oldest first
        except Exception:
            return 0
        replayed = 0
        for entry_id, fields in entries:
            f = self._decode_entry(fields)
            payload = {
                k: f[k] for k in ("request_id", "session_id", "gateway_id", "rid", "traceparent", "message") if k in f
            }
            if "message" not in payload:
                continue
            try:
                await self._r.xadd(calls_key, payload, maxlen=_CALL_STREAM_MAXLEN, approximate=True)
                await self._r.xdel(dead_key, entry_id)
                replayed += 1
            except Exception:
                logger.warning(f"Failed to replay dead-letter entry {entry_id} for {hostname}")
        return replayed

    async def dead_letter_purge(self, hostname: str, ids: list[str] | None = None) -> int:
        key = f"device:{hostname}:calls:dead"
        try:
            if ids:
                return int(await self._r.xdel(key, *ids))
            await self._r.delete(key)
            return -1  # whole DLQ dropped
        except Exception:
            return 0
