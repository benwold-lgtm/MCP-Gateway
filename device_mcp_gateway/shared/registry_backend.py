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
    ) -> None:
        """Push a tool-call message onto the device's Redis Stream."""
        ...


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
    ) -> None:
        pass  # no-op; embedded mode routes calls in-process


# ---------------------------------------------------------------------------
# Redis backend (distributed mode)
# ---------------------------------------------------------------------------

_DEVICES_SET = "devices:all"
_ASSIGNMENTS_STREAM = "device:assignments"
_WORKER_GROUP = "workers"


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
        await self._r.setex(f"device:{hostname}:manifest", ttl, json.dumps(manifest))

    async def delete_manifest(self, hostname: str) -> None:
        await self._r.delete(f"device:{hostname}:manifest")

    async def publish_assignment(self, action: str, hostname: str) -> None:
        await self._r.xadd(_ASSIGNMENTS_STREAM, {"action": action, "hostname": hostname})
        logger.debug(f"Published assignment: action={action} hostname={hostname}")

    async def publish_tool_call(
        self,
        hostname: str,
        request_id: str,
        session_id: str,
        gateway_id: str,
        message: dict,
    ) -> None:
        await self._r.xadd(
            f"device:{hostname}:calls",
            {
                "request_id": request_id,
                "session_id": session_id,
                "gateway_id": gateway_id,
                "message": json.dumps(message),
            },
        )
