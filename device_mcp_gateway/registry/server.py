"""
Central Registry Service
- Device registration and discovery
- Spec management with versioning and TTL cache
- Pod lifecycle orchestration
- Health monitoring with device reachability polling
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
from loguru import logger

from device_mcp_gateway.core.translator import SpecTranslator
from device_mcp_gateway.pods.device_pod import DevicePod
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.storage.base import AbstractDeviceStore


@dataclass
class DeviceProfile:
    """Registered device/API profile stored in the registry."""

    hostname: str
    base_url: str
    spec_url: str | None = None
    auth: AbstractAuth | None = None
    transport: str = "sse"
    spec_cache_ttl: int = 3600
    spec_data: dict[str, Any] | None = None
    spec_hash: str | None = None
    last_spec_check: float = 0.0
    reachable: bool = True
    last_reachable_check: float = 0.0
    pod: DevicePod | None = None
    pod_active: bool = False
    spawn_error: str | None = None


class SpecCache:
    """TTL-based cache for parsed OpenAPI specs."""

    def __init__(self, ttl: int = 3600, max_entries: int = 200):
        self._store: dict[str, dict[str, Any]] = {}
        self._timestamps: dict[str, float] = {}
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
        if len(self._store) >= self._max:
            oldest = min(self._timestamps, key=self._timestamps.get)
            del self._store[oldest]
            del self._timestamps[oldest]
        self._store[key] = value
        self._timestamps[key] = time.time()


class Registry:
    """Central orchestration for device discovery, spec management, pods."""

    def __init__(self, config: dict[str, Any], store: AbstractDeviceStore | None = None):
        self._config = config
        self._devices: dict[str, DeviceProfile] = {}
        self._store = store
        self._spec_cache = SpecCache(
            ttl=config.get("spec_cache_ttl", 3600),
            max_entries=200,
        )
        self._translator = SpecTranslator()
        self._health_task: asyncio.Task | None = None
        self._health_interval = config.get("health_check_interval", 30)
        self._spec_poll_interval = config.get("spec_poll_interval", 300)
        self._max_pods = config.get("max_concurrent_pods", 50)

    async def register_device(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None = None,
        auth: AbstractAuth | None = None,
        transport: str = "sse",
    ) -> DeviceProfile:
        profile = DeviceProfile(
            hostname=hostname,
            base_url=base_url,
            spec_url=spec_url,
            auth=auth,
            transport=transport,
            spec_cache_ttl=self._config.get("spec_cache_ttl", 3600),
        )
        self._devices[hostname] = profile

        if self._store:
            auth_type = None
            auth_config = None
            if auth is not None:
                d = auth.to_dict()
                auth_type = d.get("type")
                auth_config = d
            await self._store.save(
                hostname,
                {
                    "base_url": base_url,
                    "spec_url": spec_url,
                    "transport": transport,
                    "auth_type": auth_type,
                    "auth_config": auth_config,
                },
            )

        logger.info(f"Device registered: hostname={hostname}, base_url={base_url}")
        # Immediately attempt to verify reachability and spawn a pod to avoid
        # race conditions where the health loop has not yet run.
        try:
            reachable = await self.check_reachability(profile)
            if reachable:
                await self.fetch_spec(profile)
                # Only spawn if we have a spec and no active pod yet
                if profile.spec_data and not profile.pod_active:
                    await self._spawn_pod(profile)
        except Exception as exc:
            logger.exception(f"Error during immediate post-register processing for {hostname}")
            profile.spawn_error = str(exc)

        return profile

    async def deregister_device(self, hostname: str) -> None:
        profile = self._devices.pop(hostname, None)
        if profile and profile.pod_active and profile.pod:
            profile.pod.stop()
            profile.pod_active = False
        if self._store:
            await self._store.delete(hostname)
        logger.info(f"Device deregistered: {hostname}")

    def get_device(self, hostname: str) -> DeviceProfile | None:
        return self._devices.get(hostname)

    async def load_persisted_devices(self) -> None:
        """On startup, reload devices from the store and attempt to reconnect pods."""
        if not self._store:
            return
        records = await self._store.load_all()
        if not records:
            return
        logger.info(f"Loading {len(records)} persisted device(s) from store")
        for record in records:
            auth = _auth_from_record(record)
            profile = DeviceProfile(
                hostname=record["hostname"],
                base_url=record["base_url"],
                spec_url=record.get("spec_url"),
                auth=auth,
                transport=record.get("transport", "sse"),
                spec_cache_ttl=self._config.get("spec_cache_ttl", 3600),
            )
            self._devices[record["hostname"]] = profile
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
        if cached and (time.time() - profile.last_spec_check) < profile.spec_cache_ttl:
            return cached

        if profile.spec_url:
            fetched = await self._http_get(profile.spec_url)
        else:
            fetched = await self._discover_spec(profile.base_url)

        if fetched:
            import hashlib

            h = hashlib.sha256(str(fetched).encode()).hexdigest()[:16]
            if h != profile.spec_hash:
                logger.info(f"Spec updated for {profile.hostname}: hash={h}")
            profile.spec_hash = h
            profile.spec_data = fetched
            profile.last_spec_check = time.time()
            self._spec_cache.put(cache_key, fetched)
            return fetched
        return {}

    async def _discover_spec(self, base_url: str) -> dict[str, Any] | None:
        paths = self._config.get("discovery", {}).get(
            "spec_paths",
            [
                "/openapi.json",
                "/swagger.json",
                "/api-docs",
            ],
        )
        async with httpx.AsyncClient(timeout=self._config.get("discovery", {}).get("timeout", 10)) as client:
            for path in paths:
                try:
                    url = base_url.rstrip("/") + path
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return resp.json()
                except Exception:
                    continue
        return None

    async def _http_get(self, url: str) -> dict[str, Any] | None:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                return None
        return None

    async def check_reachability(self, profile: DeviceProfile) -> bool:
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                resp = await client.get(profile.base_url, follow_redirects=True)
                profile.reachable = resp.status_code < 500
            except Exception:
                profile.reachable = False
            profile.last_reachable_check = time.time()
        return profile.reachable

    async def start_health_loop(self) -> None:
        while True:
            for hostname, profile in list(self._devices.items()):
                reachable = await self.check_reachability(profile)
                if reachable:
                    await self.fetch_spec(profile)
                if profile.reachable and not profile.pod_active:
                    await self._spawn_pod(profile)
                elif not profile.reachable and profile.pod_active:
                    await self._kill_pod(profile)
            await asyncio.sleep(self._health_interval)

    async def _spawn_pod(self, profile: DeviceProfile) -> None:
        if sum(1 for p in self._devices.values() if p.pod_active) >= self._max_pods:
            logger.warning("Max pods reached, skipping spawn")
            return
        spec = profile.spec_data or await self.fetch_spec(profile)
        if not spec:
            msg = f"No spec available for {profile.hostname}, cannot spawn pod"
            logger.warning(msg)
            profile.spawn_error = msg
            return
        mcp_manifest = self._translator.translate(spec, profile.hostname)
        pod = DevicePod(
            hostname=profile.hostname,
            manifest=mcp_manifest,
            transport=profile.transport,
            auth=profile.auth,
            base_url=profile.base_url,
        )
        await pod.start()
        profile.pod = pod
        profile.pod_active = True
        logger.info(f"Pod spawned for {profile.hostname}")

    async def _kill_pod(self, profile: DeviceProfile) -> None:
        if profile.pod and profile.pod_active:
            profile.pod.stop()
            profile.pod_active = False
            logger.info(f"Pod killed for {profile.hostname}")

    async def shutdown(self) -> None:
        for profile in self._devices.values():
            await self._kill_pod(profile)
        logger.info("Registry shutdown complete")


def _auth_from_record(record: dict) -> AbstractAuth | None:
    """Reconstruct an AbstractAuth instance from a persisted record."""
    auth_config = record.get("auth_config")
    if not auth_config:
        return None
    from device_mcp_gateway.auth.api_key import ApiKeyAuth
    from device_mcp_gateway.auth.oauth2 import OAuth2Auth

    auth_type = auth_config.get("type")
    if auth_type == "api_key":
        return ApiKeyAuth.from_dict(auth_config)
    if auth_type == "oauth2":
        return OAuth2Auth.from_dict(auth_config)
    logger.warning(f"Unknown auth type in store: {auth_type}")
    return None
