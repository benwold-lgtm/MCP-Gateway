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
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any

from loguru import logger
from redis.exceptions import WatchError

from device_mcp_gateway.shared.keys import KEYS

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
    # Both of these describe a *measurement*, so neither may default to one (F-66).
    # `reachable=True` + a registration-time `last_check` meant a device nothing had
    # ever contacted read as healthy with a timestamp that aged without bound, next to
    # a `spawn_error` saying it had failed. The honest defaults are "not established"
    # and "never checked": `last_check=0.0` already renders as a null `last_check` /
    # `last_check_age_seconds` through the response models, so a client can tell "never
    # checked" from "checked and dead" without the tri-state that would break the shape.
    reachable: bool = False
    last_check: float = 0.0
    spawn_error: str | None = None
    worker_id: str | None = None
    # Monotonic counter bumped whenever a spec change mutated the generated tool
    # set (F-41). A client polls this to detect "the tools moved under me" and
    # re-list; the audit stream records what changed and whether it was breaking.
    tools_revision: int = 0
    # What the upstream SPEAKS: "openapi" (a document this gateway translates into tools)
    # or "mcp" (a server this gateway proxies). A remote MCP server is deliberately the
    # same entity as a device rather than a new one — see docs/adr/0009. The default keeps
    # every record written before passthrough existed reading as what it is.
    upstream_kind: str = "openapi"
    # How this gateway TALKS to an "mcp" upstream: "http" (Streamable HTTP) or "sse".
    # Unused when upstream_kind is "openapi". Distinct from ``transport`` above, which is
    # INBOUND — how the pod serves MCP to its own clients — and must stay "sse".
    upstream_transport: str = "http"

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

        # `reachable` is only ever true alongside the check that established it (F-66).
        # Its writers set both fields in one call, so this is an invariant rather than a
        # repair — but it is the one place every distributed read passes through, and it
        # keeps a future writer from reintroducing a truth claim with nothing behind it.
        last_check = float(h.get("last_check", "0") or "0")

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
            reachable=h.get("reachable", "") == "True" and last_check > 0,
            last_check=last_check,
            spawn_error=_opt_str(h.get("spawn_error", "")),
            worker_id=_opt_str(h.get("worker_id", "")),
            tools_revision=int(h.get("tools_revision", "0") or "0"),
            # `or` rather than a dict default: a hash written before these fields existed
            # has no key at all, and to_redis_hash writes "" for an unset value. Both must
            # land on the default — an empty upstream_kind would match no branch and route
            # the device nowhere.
            upstream_kind=h.get("upstream_kind", "") or "openapi",
            upstream_transport=h.get("upstream_transport", "") or "http",
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
    async def update_device_fields(self, hostname: str, **fields: Any) -> bool:
        """Partial update — only write the supplied fields.

        Must **not** create the record: a device that has been deleted stays deleted.
        Returns True when the update applied, False when there was no record to update.
        """
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

    async def touch_manifest(self, hostname: str, ttl: int) -> bool:
        """Extend a cached manifest's lease, reporting whether there was one to extend.

        The manifest is stored with a TTL so a device no longer served by any worker
        stops being cached. That only works if the worker actually serving it keeps
        renewing the lease — otherwise the cache expires under a live pod. Returns
        False when the key is already gone, which tells the caller to rebuild.

        Default implementation is for backends that do not expire manifests at all
        (the in-memory one), where a stored manifest is always still there.
        """
        return await self.get_manifest(hostname) is not None

    # Tool-set change governance (F-41). Non-abstract with a safe default so a
    # backend (or test double) that doesn't persist the last change still works —
    # the diff endpoint then simply reports "no change recorded".
    async def get_last_tool_change(self, hostname: str) -> dict | None:
        """The most recent recorded tool-set change for a device, or None."""
        return None

    async def set_last_tool_change(self, hostname: str, change: dict) -> None:
        """Persist the most recent tool-set change (added/removed/changed/breaking)."""
        return None

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
        self._tool_changes: dict[str, dict] = {}

    async def initialize(self) -> None:
        pass

    async def get_device(self, hostname: str) -> DeviceConfig | None:
        return self._devices.get(hostname)

    async def set_device(self, hostname: str, config: DeviceConfig) -> None:
        self._devices[hostname] = config

    async def update_device_fields(self, hostname: str, **fields: Any) -> bool:
        cfg = self._devices.get(hostname)
        if not cfg:
            return False
        for k, v in fields.items():
            setattr(cfg, k, v)
        return True

    async def delete_device(self, hostname: str) -> None:
        self._devices.pop(hostname, None)
        self._tool_changes.pop(hostname, None)

    async def list_hostnames(self) -> list[str]:
        return list(self._devices.keys())

    async def get_manifest(self, hostname: str) -> dict | None:
        return self._manifests.get(hostname)

    async def set_manifest(self, hostname: str, manifest: dict, ttl: int) -> None:
        self._manifests[hostname] = manifest

    async def delete_manifest(self, hostname: str) -> None:
        self._manifests.pop(hostname, None)

    async def get_last_tool_change(self, hostname: str) -> dict | None:
        return self._tool_changes.get(hostname)

    async def set_last_tool_change(self, hostname: str, change: dict) -> None:
        self._tool_changes[hostname] = change

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

# Unassign is delivered on a SEPARATE stream that every worker tails independently
# (broadcast), not via the shared competing-consumers group. An "assign" only needs
# one worker to act, but an "unassign" must reach whichever worker actually owns the
# pod — and on the shared group it landed on one arbitrary worker that usually wasn't
# the owner, so the pod was never torn down and a PUT-replace never applied its new
# config. Bounded so a churny fleet can't grow it without limit.
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
      device:{hostname}:tools_change → String (JSON, no TTL — last tool-set diff)
      device:assignments           → Stream {action, hostname}
      device:{hostname}:calls      → Stream {request_id, session_id, gateway_id, message}
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client

    async def initialize(self) -> None:
        # Ensure consumer group exists for the assignments stream.
        try:
            await self._r.xgroup_create(KEYS.assignments_stream, KEYS.worker_group, id="0", mkstream=True)
            logger.info("Created Redis consumer group 'workers' on device:assignments")
        except Exception as exc:
            if "BUSYGROUP" in str(exc):
                pass  # group already exists — normal on restart
            else:
                logger.warning(f"xgroup_create warning: {exc}")

    @staticmethod
    def _config_or_none(hostname: str, h: dict[str, str]) -> "DeviceConfig | None":
        """Decode a config hash, treating a *partial* one as absent rather than raising.

        A hash with no ``hostname`` field is not a device — it is wreckage. The write
        path can no longer produce one (see ``update_device_fields``), but a record
        left behind by a version that could must still read as "no such device"
        instead of raising ``KeyError`` out of every endpoint that touches it. Once it
        reads as absent, re-registering the hostname overwrites it and the wreckage
        clears itself.
        """
        if not h:
            return None
        if "hostname" not in h:
            logger.warning(
                f"Ignoring a partial device record at {KEYS.device_config(hostname)} "
                f"(fields: {sorted(h)}) — no hostname, so it cannot be a device. Left over from "
                f"a delete that raced a field update; re-registering {hostname} will overwrite it."
            )
            return None
        return DeviceConfig.from_redis_hash(h)

    async def get_device(self, hostname: str) -> DeviceConfig | None:
        h = await self._r.hgetall(KEYS.device_config(hostname))
        return self._config_or_none(hostname, h)

    async def get_devices(self, hostnames: list[str]) -> list[DeviceConfig]:
        """Fetch all device configs in a single pipeline (avoids N round-trips)."""
        if not hostnames:
            return []
        pipe = self._r.pipeline()
        for h in hostnames:
            pipe.hgetall(KEYS.device_config(h))
        raw_hashes = await pipe.execute()
        configs = [self._config_or_none(host, raw) for host, raw in zip(hostnames, raw_hashes)]
        return [c for c in configs if c is not None]

    async def set_device(self, hostname: str, config: DeviceConfig) -> None:
        pipe = self._r.pipeline()
        pipe.hset(KEYS.device_config(hostname), mapping=config.to_redis_hash())
        pipe.sadd(KEYS.devices_set, hostname)
        await pipe.execute()

    async def update_device_fields(self, hostname: str, **fields: Any) -> bool:
        """Partial update that will **not** create the record. Returns whether it applied.

        A plain ``HSET`` creates the key when it is missing, which is how a deleted
        device came back as wreckage: ``DELETE`` removes ``device:{h}:config`` and drops
        the hostname from ``devices:all``, then a worker that still had the device
        assigned wrote ``pod_active``/``worker_id`` and re-created the hash with just
        those two fields. The result was invisible to ``GET /v1/devices`` (which reads
        the set) while every read *by hostname* raised ``KeyError: 'hostname'`` as a 500
        — and re-registering the hostname failed too, because registration reads the
        device first. Found on a cluster, not here.

        ``WATCH``/``MULTI`` rather than a check-then-write: the delete can land between
        the two, and an ``EXISTS``-then-``HSET`` would lose that race exactly as before.
        The transaction aborts if the key changes under us, and the retry re-reads a now
        missing key and reports ``False``. ``MemoryRegistryBackend`` never had the bug —
        it guards with ``if cfg`` — which is why the embedded suite could not see this.
        """
        mapping = {k: "" if v is None else str(v) for k, v in fields.items()}
        key = KEYS.device_config(hostname)
        async with self._r.pipeline() as pipe:
            while True:
                try:
                    await pipe.watch(key)
                    if not await pipe.exists(key):
                        await pipe.reset()
                        logger.debug(f"Skipped field update for {hostname}: the device record is gone")
                        return False
                    pipe.multi()
                    pipe.hset(key, mapping=mapping)
                    await pipe.execute()
                    return True
                except WatchError:
                    continue  # the record changed mid-flight; re-read and decide again

    async def delete_device(self, hostname: str) -> None:
        pipe = self._r.pipeline()
        pipe.delete(KEYS.device_config(hostname))
        pipe.delete(KEYS.device_manifest(hostname))
        pipe.delete(KEYS.device_tools_change(hostname))
        # Drop the tool-call stream and its dead-letter stream too, or they linger
        # in Redis after the device is gone and accumulate over churn (RC-4, SRE #4).
        pipe.delete(KEYS.device_calls(hostname))
        pipe.delete(KEYS.device_calls_dead(hostname))
        pipe.srem(KEYS.devices_set, hostname)
        await pipe.execute()

    async def list_hostnames(self) -> list[str]:
        return list(await self._r.smembers(KEYS.devices_set))

    async def get_manifest(self, hostname: str) -> dict | None:
        raw = await self._r.get(KEYS.device_manifest(hostname))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set_manifest(self, hostname: str, manifest: dict, ttl: int) -> None:
        await self._r.set(KEYS.device_manifest(hostname), json.dumps(manifest), ex=ttl)

    async def delete_manifest(self, hostname: str) -> None:
        await self._r.delete(KEYS.device_manifest(hostname))

    async def touch_manifest(self, hostname: str, ttl: int) -> bool:
        # EXPIRE returns 0 when the key does not exist, which is exactly the
        # "cache already lapsed, rebuild it" signal the health loop needs — and
        # it costs one round trip on the common path, unlike a GET-then-SET.
        return bool(await self._r.expire(KEYS.device_manifest(hostname), ttl))

    async def get_last_tool_change(self, hostname: str) -> dict | None:
        # Governance metadata — stored without a TTL (unlike the manifest) so the
        # "what last changed" answer outlives the spec cache; cleaned up on delete.
        raw = await self._r.get(KEYS.device_tools_change(hostname))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set_last_tool_change(self, hostname: str, change: dict) -> None:
        await self._r.set(KEYS.device_tools_change(hostname), json.dumps(change))

    async def publish_assignment(self, action: str, hostname: str) -> None:
        if action == "unassign":
            # Broadcast: every worker tails this stream so the actual owner tears down
            # its pod (non-owners no-op). See KEYS.unassign_stream rationale above.
            await self._r.xadd(
                KEYS.unassign_stream, {"hostname": hostname}, maxlen=_UNASSIGN_STREAM_MAXLEN, approximate=True
            )
        else:
            await self._r.xadd(KEYS.assignments_stream, {"action": action, "hostname": hostname})
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
            KEYS.device_calls(hostname),
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
        group = KEYS.device_calls_group(hostname)
        try:
            groups = await self._r.xinfo_groups(KEYS.device_calls(hostname))
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
        key = KEYS.device_calls_dead(hostname)
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
        dead_key = KEYS.device_calls_dead(hostname)
        calls_key = KEYS.device_calls(hostname)
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
        key = KEYS.device_calls_dead(hostname)
        try:
            if ids:
                return int(await self._r.xdel(key, *ids))
            await self._r.delete(key)
            return -1  # whole DLQ dropped
        except Exception:
            return 0
