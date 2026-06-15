# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""SpecService — outbound OpenAPI spec acquisition for embedded mode (F-12).

Extracted from the Registry god-object. Owns everything about *getting* a
device's spec: the shared httpx client (with F-31 outbound mTLS), URL fetch and
multi-path discovery, the bounded TTL cache, and recording the fetched spec on
the DeviceProfile (+ persisting its hash/last_check).

It deliberately knows nothing about pods. The old ``fetch_spec`` replaced a
running pod inline when the spec changed — a spec↔pod recursion that made the
Registry a god-object. Here ``fetch_spec`` instead **returns whether the spec
changed**, and the caller (provisioning / health loop) decides whether to ask the
PodSupervisor to replace the pod.
"""

from __future__ import annotations

import asyncio
import hashlib
import heapq
import time
from typing import Any

import httpx
from loguru import logger

from device_mcp_gateway.audit import redact_url
from device_mcp_gateway.core.backoff import RetryPolicy, send_with_retry
from device_mcp_gateway.core.spec_limits import (
    DEFAULT_MAX_SPEC_BYTES,
    SpecTooLargeError,
    fetched_spec_or_none,
)
from device_mcp_gateway.registry.models import DeviceProfile
from device_mcp_gateway.shared.registry_backend import AbstractRegistryBackend


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


class SpecService:
    """Fetches, discovers, and caches device specs. No pod knowledge."""

    def __init__(
        self,
        *,
        backend: AbstractRegistryBackend,
        config: dict[str, Any],
        tls_verify: Any,
        retry_policy: RetryPolicy,
    ) -> None:
        self._backend = backend
        self._config = config
        self._tls_verify = tls_verify
        self._retry_policy = retry_policy
        self._spec_max_bytes = config.get("spec_max_bytes", DEFAULT_MAX_SPEC_BYTES)
        self._spec_poll_interval = config.get("spec_poll_interval", 300)
        self._cache = SpecCache(ttl=config.get("spec_cache_ttl", 3600), max_entries=200)
        self._http_client: httpx.AsyncClient | None = None

    def client(self) -> httpx.AsyncClient:
        """The shared outbound client (also used by Registry reachability probes).

        One client per registry instance keeps connections/TLS warm across the
        reachability and spec-fetch GETs to the same device.
        """
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(follow_redirects=True, verify=self._tls_verify)
        return self._http_client

    def invalidate(self, base_url: str) -> None:
        self._cache.invalidate(base_url)

    async def aclose(self) -> None:
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    async def fetch_spec(self, profile: DeviceProfile) -> bool:
        """Fetch + cache the device's spec, recording it on ``profile``.

        Updates ``profile.spec_data`` / ``spec_hash`` / ``last_check`` and persists
        hash + last_check. Returns ``True`` when the spec **changed** vs. the
        device's previous hash (so the caller can replace a running pod); ``False``
        on first fetch, unchanged spec, or fetch failure. Does not touch pods.
        """
        cache_key = profile.base_url
        cached = self._cache.get(cache_key)
        if cached and (time.time() - profile.config.last_check) < self._spec_poll_interval:
            profile.spec_data = cached
            return False

        if profile.spec_url:
            fetched = await self._http_get(profile.spec_url)
        else:
            fetched = await self._discover_spec(profile.base_url)

        if not fetched:
            return False

        h = hashlib.sha256(str(fetched).encode()).hexdigest()[:16]
        old_hash = profile.config.spec_hash
        profile.config.spec_hash = h
        profile.spec_data = fetched
        profile.config.last_check = time.time()
        self._cache.put(cache_key, fetched)
        await self._backend.update_device_fields(profile.hostname, spec_hash=h, last_check=profile.config.last_check)

        changed = old_hash is not None and h != old_hash
        if changed:
            logger.info(f"Spec changed for {profile.hostname}: {old_hash} → {h}")
        else:
            logger.debug(f"Spec fetched for {profile.hostname}: hash={h}")
        return changed

    async def _discover_spec(self, base_url: str) -> dict[str, Any] | None:
        paths = self._config.get("discovery", {}).get(
            "spec_paths",
            ["/openapi.json", "/swagger.json", "/api-docs"],
        )
        timeout = self._config.get("discovery", {}).get("timeout", 10)
        client = self.client()

        async def _probe(path: str) -> dict[str, Any] | None:
            url = base_url.rstrip("/") + path
            try:

                async def _get(u: str = url) -> httpx.Response:
                    return await client.get(u, timeout=timeout)

                resp = await send_with_retry(_get, method="GET", policy=self._retry_policy)
                return fetched_spec_or_none(resp, max_bytes=self._spec_max_bytes)
            except SpecTooLargeError as exc:
                logger.warning(f"Spec discovery rejected oversized spec at {redact_url(url)}: {exc} (F-09)")
                return None
            except (httpx.HTTPError, ValueError) as exc:
                logger.debug(f"Spec discovery probe failed for {redact_url(url)}: {exc}")
                return None

        # Probe candidate paths concurrently and take the first that yields a valid
        # spec, so worst-case discovery latency is one path's timeout, not the sum of
        # all of them (F-11). Losing probes are cancelled once we have a winner.
        tasks = [asyncio.create_task(_probe(p)) for p in paths]
        try:
            for fut in asyncio.as_completed(tasks):
                spec = await fut
                if spec is not None:
                    return spec
            return None
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _http_get(self, url: str) -> dict[str, Any] | None:
        try:
            resp = await send_with_retry(
                lambda: self.client().get(url, timeout=10), method="GET", policy=self._retry_policy
            )
            return fetched_spec_or_none(resp, max_bytes=self._spec_max_bytes)
        except SpecTooLargeError as exc:
            logger.warning(f"Spec fetch rejected oversized spec at {redact_url(url)}: {exc} (F-09)")
            return None
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug(f"Spec fetch failed for {redact_url(url)}: {exc}")
            return None
