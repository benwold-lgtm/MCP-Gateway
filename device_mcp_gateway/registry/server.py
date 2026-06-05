# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""
Central Registry Service

In embedded mode (registry.mode = "embedded"):
  - All device state kept in MemoryRegistryBackend (in-process dict)
  - DevicePods spawned as asyncio tasks in this process
  - Health loop runs here
  - SQLite (AbstractDeviceStore) used for credential persistence

In distributed mode (registry.mode = "distributed"):
  - All device state kept in RedisRegistryBackend
  - Pod lifecycle owned by worker processes; Registry is a thin API layer
  - Health loop runs in workers
  - Credentials stored encrypted in Redis (no SQLite)
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import heapq
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Any

import httpx
from loguru import logger

from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.core.translator import SpecTranslator
from device_mcp_gateway.pods.device_pod import DevicePod
from device_mcp_gateway.shared.registry_backend import (
    AbstractRegistryBackend,
    DeviceConfig,
    MemoryRegistryBackend,
)
from device_mcp_gateway.storage.base import AbstractDeviceStore

_spec_executor = ProcessPoolExecutor(max_workers=4)


def _shutdown_spec_executor() -> None:
    """Reap the spec-translation worker processes at interpreter exit (RC-5).

    Registered with atexit rather than called from Registry.shutdown() because
    the executor is process-global and shared across Registry instances —
    shutting it down per-instance would break reuse.
    """
    _spec_executor.shutdown(wait=False)


atexit.register(_shutdown_spec_executor)


def _translate_spec_sync(spec: dict, hostname: str) -> Any:
    """Run in a worker process to avoid blocking the event loop."""
    return SpecTranslator().translate(spec, hostname)


# ---------------------------------------------------------------------------
# DeviceProfile — embedded-mode runtime state (wraps DeviceConfig + pod)
# ---------------------------------------------------------------------------


@dataclass
class DeviceProfile:
    """Runtime device state used only in embedded mode.

    Holds the DeviceConfig plus asyncio/pod references that cannot be
    serialised to Redis.
    """

    config: DeviceConfig
    auth: AbstractAuth | None = None
    spec_data: dict[str, Any] | None = None
    pod: DevicePod | None = None

    # Convenience pass-throughs so call-sites don't need to know about .config
    @property
    def hostname(self) -> str:
        return self.config.hostname

    @property
    def base_url(self) -> str:
        return self.config.base_url

    @property
    def spec_url(self) -> str | None:
        return self.config.spec_url

    @property
    def transport(self) -> str:
        return self.config.transport

    @property
    def rate_limit_rps(self) -> float | None:
        return self.config.rate_limit_rps

    @property
    def reachable(self) -> bool:
        return self.config.reachable

    @property
    def pod_active(self) -> bool:
        return self.config.pod_active

    @property
    def last_reachable_check(self) -> float:
        return self.config.last_check

    @property
    def spawn_error(self) -> str | None:
        return self.config.spawn_error

    @property
    def spec_hash(self) -> str | None:
        return self.config.spec_hash


# ---------------------------------------------------------------------------
# SpecCache (embedded mode only)
# ---------------------------------------------------------------------------


class SpecCache:
    """TTL-based in-memory cache for raw OpenAPI spec dicts.

    Eviction is O(log n) via a min-heap ordered by insertion timestamp.
    Stale heap entries (from updates to existing keys) are cleaned up lazily.
    """

    def __init__(self, ttl: int = 3600, max_entries: int = 200):
        self._store: dict[str, dict[str, Any]] = {}
        self._timestamps: dict[str, float] = {}
        self._heap: list[tuple[float, str]] = []  # (inserted_at, key)
        self._ttl = ttl
        self._max = max_entries

    def get(self, key: str) -> dict[str, Any] | None:
        if key not in self._store:
            return None
        if time.time() - self._timestamps[key] > self._ttl:
            del self._store[key]
            del self._timestamps[key]
            return None
        return self._store[key]

    def put(self, key: str, value: dict[str, Any]) -> None:
        if len(self._store) >= self._max and key not in self._store:
            self._evict_oldest()
        ts = time.time()
        self._store[key] = value
        self._timestamps[key] = ts
        heapq.heappush(self._heap, (ts, key))

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)
        self._timestamps.pop(key, None)
        # Heap entry becomes stale; cleaned up lazily on next eviction.

    def _evict_oldest(self) -> None:
        while self._heap:
            ts, key = self._heap[0]
            # Skip stale entries (key updated or invalidated since this was pushed).
            if key not in self._timestamps or self._timestamps[key] != ts:
                heapq.heappop(self._heap)
                continue
            heapq.heappop(self._heap)
            del self._store[key]
            del self._timestamps[key]
            return


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class Registry:
    """Device registry — thin API layer over AbstractRegistryBackend.

    In embedded mode it also orchestrates pod lifecycle and health checks.
    In distributed mode it is read/write only; workers own pods and health.
    """

    def __init__(
        self,
        config: dict[str, Any],
        backend: AbstractRegistryBackend | None = None,
        store: AbstractDeviceStore | None = None,
    ):
        self._config = config
        self._mode = config.get("mode", "embedded")
        self._backend: AbstractRegistryBackend = backend or MemoryRegistryBackend()
        self._store = store  # SQLite credential store (embedded mode only)

        # Embedded-mode runtime state (not used in distributed mode)
        self._profiles: dict[str, DeviceProfile] = {}
        self._device_locks: dict[str, asyncio.Lock] = {}
        self._spec_cache = SpecCache(
            ttl=config.get("spec_cache_ttl", 3600),
            max_entries=200,
        )
        self._health_task: asyncio.Task | None = None
        self._health_interval = config.get("health_check_interval", 30)
        self._spec_poll_interval = config.get("spec_poll_interval", 300)
        self._max_pods = config.get("max_concurrent_pods", 50)
        self._http_client: httpx.AsyncClient | None = None
        self._health_semaphore = asyncio.Semaphore(config.get("max_concurrent_health_checks", 10))

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _lock_for(self, hostname: str) -> asyncio.Lock:
        if hostname not in self._device_locks:
            self._device_locks[hostname] = asyncio.Lock()
        return self._device_locks[hostname]

    def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(follow_redirects=True)
        return self._http_client

    # ------------------------------------------------------------------
    # Device management (shared between modes)
    # ------------------------------------------------------------------

    async def register_device(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None = None,
        auth: AbstractAuth | None = None,
        transport: str = "sse",
        rate_limit_rps: float | None = None,
    ) -> DeviceConfig:
        """POST semantics: create a new device."""
        if self._mode == "distributed":
            return await self._register_distributed(hostname, base_url, spec_url, auth, transport, rate_limit_rps)
        async with self._lock_for(hostname):
            profile = await self._setup_device_nolock(hostname, base_url, spec_url, auth, transport, rate_limit_rps)
            return profile.config

    async def replace_device(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None = None,
        auth: AbstractAuth | None = None,
        transport: str = "sse",
        rate_limit_rps: float | None = None,
    ) -> DeviceConfig:
        """PUT semantics: kill existing pod and re-register atomically."""
        if self._mode == "distributed":
            await self._backend.publish_assignment("unassign", hostname)
            return await self._register_distributed(hostname, base_url, spec_url, auth, transport, rate_limit_rps)
        async with self._lock_for(hostname):
            existing = self._profiles.get(hostname)
            if existing:
                await self._kill_pod(existing)
                self._spec_cache.invalidate(existing.base_url)
            profile = await self._setup_device_nolock(hostname, base_url, spec_url, auth, transport, rate_limit_rps)
            return profile.config

    async def deregister_device(self, hostname: str) -> None:
        if self._mode == "distributed":
            await self._backend.publish_assignment("unassign", hostname)
            await self._backend.delete_device(hostname)
            logger.info(f"Device deregistered (distributed): {hostname}")
            return
        async with self._lock_for(hostname):
            profile = self._profiles.pop(hostname, None)
            if profile and profile.pod_active and profile.pod:
                await self._kill_pod(profile)
        self._device_locks.pop(hostname, None)
        if self._store:
            await self._store.delete(hostname)
        await self._backend.delete_device(hostname)
        logger.info(f"Device deregistered: {hostname}")

    async def get_device(self, hostname: str) -> DeviceConfig | None:
        if self._mode == "distributed":
            return await self._backend.get_device(hostname)
        profile = self._profiles.get(hostname)
        return profile.config if profile else None

    async def list_devices(self) -> list[DeviceConfig]:
        if self._mode == "distributed":
            hostnames = await self._backend.list_hostnames()
            configs = []
            for h in hostnames:
                cfg = await self._backend.get_device(h)
                if cfg:
                    configs.append(cfg)
            return configs
        return [p.config for p in self._profiles.values()]

    async def get_manifest(self, hostname: str) -> dict | None:
        return await self._backend.get_manifest(hostname)

    # ------------------------------------------------------------------
    # Distributed mode helpers
    # ------------------------------------------------------------------

    async def _register_distributed(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None,
        auth: AbstractAuth | None,
        transport: str,
        rate_limit_rps: float | None,
    ) -> DeviceConfig:
        auth_type, auth_config_str = _auth_to_record(auth)
        cfg = DeviceConfig(
            hostname=hostname,
            base_url=base_url,
            spec_url=spec_url,
            transport=transport,
            auth_type=auth_type,
            auth_config=auth_config_str,
            rate_limit_rps=rate_limit_rps,
        )
        await self._backend.set_device(hostname, cfg)
        await self._backend.publish_assignment("assign", hostname)
        logger.info(f"Device registered (distributed): {hostname}")
        return cfg

    # ------------------------------------------------------------------
    # Embedded mode: pod lifecycle
    # ------------------------------------------------------------------

    async def _setup_device_nolock(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None,
        auth: AbstractAuth | None,
        transport: str,
        rate_limit_rps: float | None,
    ) -> DeviceProfile:
        """Caller must hold _lock_for(hostname)."""
        auth_type, auth_config_str = _auth_to_record(auth)
        cfg = DeviceConfig(
            hostname=hostname,
            base_url=base_url,
            spec_url=spec_url,
            transport=transport,
            auth_type=auth_type,
            auth_config=auth_config_str,
            rate_limit_rps=rate_limit_rps,
        )
        profile = DeviceProfile(config=cfg, auth=auth)
        self._profiles[hostname] = profile
        await self._backend.set_device(hostname, cfg)

        if self._store:
            await self._store.save(
                hostname,
                {
                    "base_url": base_url,
                    "spec_url": spec_url,
                    "transport": transport,
                    "auth_type": auth_type,
                    "auth_config": auth.to_dict() if auth else None,
                    "rate_limit_rps": rate_limit_rps,
                },
            )

        logger.info(f"Device registered: hostname={hostname}, base_url={base_url}")
        try:
            reachable = await self.check_reachability(profile)
            if reachable:
                await self.fetch_spec(profile)
                if profile.spec_data and not profile.pod_active:
                    await self._spawn_pod(profile)
        except Exception as exc:
            logger.exception(f"Error during post-register processing for {hostname}")
            profile.config.spawn_error = str(exc)

        return profile

    async def load_persisted_devices(self) -> None:
        """Embedded mode: reload devices from SQLite on startup."""
        if self._mode == "distributed" or not self._store:
            return
        records = await self._store.load_all()
        if not records:
            return
        logger.info(f"Loading {len(records)} persisted device(s) from store")
        for i, record in enumerate(records):
            if i > 0:
                await asyncio.sleep(0.5)  # stagger spec fetches to avoid thundering herd
            auth = _auth_from_record(record)
            cfg = DeviceConfig(
                hostname=record["hostname"],
                base_url=record["base_url"],
                spec_url=record.get("spec_url"),
                transport=record.get("transport", "sse"),
                rate_limit_rps=record.get("rate_limit_rps"),
            )
            profile = DeviceProfile(config=cfg, auth=auth)
            self._profiles[record["hostname"]] = profile
            await self._backend.set_device(record["hostname"], cfg)
            try:
                reachable = await self.check_reachability(profile)
                if reachable:
                    await self.fetch_spec(profile)
                    if profile.spec_data and not profile.pod_active:
                        await self._spawn_pod(profile)
            except Exception:
                logger.exception(f"Error reconnecting persisted device {record['hostname']}")

    async def fetch_spec(self, profile: DeviceProfile) -> dict[str, Any]:
        cache_key = profile.base_url
        cached = self._spec_cache.get(cache_key)
        if cached and (time.time() - profile.config.last_check) < self._spec_poll_interval:
            return cached

        if profile.spec_url:
            fetched = await self._http_get(profile.spec_url)
        else:
            fetched = await self._discover_spec(profile.base_url)

        if fetched:
            h = hashlib.sha256(str(fetched).encode()).hexdigest()[:16]
            old_hash = profile.config.spec_hash
            profile.config.spec_hash = h
            profile.spec_data = fetched
            profile.config.last_check = time.time()
            self._spec_cache.put(cache_key, fetched)
            await self._backend.update_device_fields(
                profile.hostname, spec_hash=h, last_check=profile.config.last_check
            )

            if old_hash is not None and h != old_hash:
                logger.info(f"Spec changed for {profile.hostname}: {old_hash} → {h}")
                if profile.pod_active:
                    logger.info(f"Replacing pod for {profile.hostname} due to spec change")
                    await self._kill_pod(profile)
                    await self._spawn_pod(profile)
            else:
                logger.debug(f"Spec fetched for {profile.hostname}: hash={h}")

            return fetched
        return {}

    async def _discover_spec(self, base_url: str) -> dict[str, Any] | None:
        paths = self._config.get("discovery", {}).get(
            "spec_paths",
            ["/openapi.json", "/swagger.json", "/api-docs"],
        )
        timeout = self._config.get("discovery", {}).get("timeout", 10)
        client = self._get_client()
        for path in paths:
            try:
                url = base_url.rstrip("/") + path
                resp = await client.get(url, timeout=timeout)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                continue
        return None

    async def _http_get(self, url: str) -> dict[str, Any] | None:
        try:
            resp = await self._get_client().get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            return None
        return None

    async def check_reachability(self, profile: DeviceProfile) -> bool:
        try:
            resp = await self._get_client().get(profile.base_url, timeout=5)
            profile.config.reachable = resp.status_code < 500
        except Exception:
            profile.config.reachable = False
        profile.config.last_check = time.time()
        await self._backend.update_device_fields(
            profile.hostname, reachable=profile.config.reachable, last_check=profile.config.last_check
        )
        return profile.config.reachable

    async def _health_check_one(self, profile: DeviceProfile) -> None:
        async with self._health_semaphore:
            async with self._lock_for(profile.hostname):
                if profile.hostname not in self._profiles:
                    return
                try:
                    reachable = await self.check_reachability(profile)
                    if reachable:
                        await self.fetch_spec(profile)
                    if profile.reachable and not profile.pod_active:
                        await self._spawn_pod(profile)
                    elif not profile.reachable and profile.pod_active:
                        await self._kill_pod(profile)
                except Exception:
                    logger.exception(f"Health check error for {profile.hostname}")

    async def start_health_loop(self) -> None:
        """Embedded mode only. Distributed mode health is handled by workers."""
        while True:
            profiles = list(self._profiles.values())
            if profiles:
                await asyncio.gather(*[self._health_check_one(p) for p in profiles])
            await asyncio.sleep(self._health_interval)

    async def _spawn_pod(self, profile: DeviceProfile) -> None:
        if sum(1 for p in self._profiles.values() if p.pod_active) >= self._max_pods:
            logger.warning("Max pods reached, skipping spawn")
            return
        spec = profile.spec_data or await self.fetch_spec(profile)
        if not spec:
            msg = f"No spec available for {profile.hostname}, cannot spawn pod"
            logger.warning(msg)
            profile.config.spawn_error = msg
            return
        loop = asyncio.get_event_loop()
        mcp_manifest = await loop.run_in_executor(_spec_executor, partial(_translate_spec_sync, spec, profile.hostname))
        keep_alive = self._config.get("transport", {}).get("sse", {}).get("keep_alive_interval", 30)
        pod = DevicePod(
            hostname=profile.hostname,
            manifest=mcp_manifest,
            transport=profile.transport,
            auth=profile.auth,
            base_url=profile.base_url,
            rate_limit_rps=profile.rate_limit_rps,
            keep_alive_interval=keep_alive,
        )
        await pod.start()
        profile.pod = pod
        profile.config.pod_active = True
        profile.config.spawn_error = None
        await self._backend.update_device_fields(profile.hostname, pod_active=True, spawn_error=None)
        logger.info(f"Pod spawned for {profile.hostname}")

    async def _kill_pod(self, profile: DeviceProfile) -> None:
        if profile.pod and profile.pod_active:
            profile.pod.stop()
            profile.config.pod_active = False
            await self._backend.update_device_fields(profile.hostname, pod_active=False)
            logger.info(f"Pod killed for {profile.hostname}")

    # ------------------------------------------------------------------
    # Embedded mode: backward-compat accessor (used by main.py routes)
    # ------------------------------------------------------------------

    def get_profile(self, hostname: str) -> DeviceProfile | None:
        """Return the local DeviceProfile (embedded mode only)."""
        return self._profiles.get(hostname)

    async def shutdown(self) -> None:
        for profile in self._profiles.values():
            await self._kill_pod(profile)
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
        logger.info("Registry shutdown complete")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _auth_to_record(auth: AbstractAuth | None) -> tuple[str | None, str | None]:
    """Return (auth_type, serialised_auth_config_str) for storage."""
    if auth is None:
        return None, None
    d = auth.to_dict()
    import json

    return d.get("type"), json.dumps(d)


def _auth_from_record(record: dict) -> AbstractAuth | None:
    from device_mcp_gateway.auth.api_key import ApiKeyAuth
    from device_mcp_gateway.auth.oauth2 import OAuth2Auth

    auth_config = record.get("auth_config")
    if not auth_config:
        return None
    if isinstance(auth_config, str):
        import json

        try:
            auth_config = json.loads(auth_config)
        except json.JSONDecodeError:
            return None
    auth_type = auth_config.get("type")
    if auth_type == "api_key":
        return ApiKeyAuth.from_dict(auth_config)
    if auth_type == "oauth2":
        return OAuth2Auth.from_dict(auth_config)
    logger.warning(f"Unknown auth type in store: {auth_type}")
    return None
