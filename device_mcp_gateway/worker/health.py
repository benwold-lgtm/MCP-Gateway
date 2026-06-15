# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Distributed health loop for device workers.

Each worker runs this loop for its assigned devices.  A Redis SETNX lock
ensures exactly one worker checks each device per interval — other workers
skip devices they can't lock and let the lock-holder update Redis.
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import ssl
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Any

import httpx
from loguru import logger

from device_mcp_gateway.core.backoff import RetryPolicy, jittered, send_with_retry
from device_mcp_gateway.core.manifest_diff import record_tool_change
from device_mcp_gateway.core.spec_limits import (
    DEFAULT_MAX_SPEC_BYTES,
    DEFAULT_TRANSLATE_TIMEOUT,
    SpecTooLargeError,
    fetched_spec_or_none,
    run_translation,
)
from device_mcp_gateway.security.url_policy import build_guarded_client
from device_mcp_gateway.shared.registry_backend import AbstractRegistryBackend

_spec_executor = ProcessPoolExecutor(max_workers=2)


def _shutdown_spec_executor() -> None:
    """Reap the spec-translation worker processes at interpreter exit (RC-5)."""
    _spec_executor.shutdown(wait=False)


atexit.register(_shutdown_spec_executor)


def _translate_spec_sync(spec: dict, hostname: str) -> Any:
    from device_mcp_gateway.core.translator import SpecTranslator

    return SpecTranslator().translate(spec, hostname)


class WorkerHealthLoop:
    """Runs health checks for a worker's assigned devices."""

    def __init__(
        self,
        worker_id: str,
        backend: AbstractRegistryBackend,
        redis_client: Any,
        interval: int = 30,
        spec_poll_interval: int = 300,
        spec_cache_ttl: int = 3600,
        discovery_cfg: dict | None = None,
        lock_ttl: int | None = None,
        retry_policy: RetryPolicy | None = None,
        spec_max_bytes: int = DEFAULT_MAX_SPEC_BYTES,
        spec_translate_timeout: float = DEFAULT_TRANSLATE_TIMEOUT,
        tls_verify: ssl.SSLContext | bool = True,
        allow_private: bool = False,
    ) -> None:
        self._worker_id = worker_id
        self._backend = backend
        self._r = redis_client
        self._interval = interval
        self._spec_poll_interval = spec_poll_interval
        self._spec_cache_ttl = spec_cache_ttl
        self._discovery = discovery_cfg or {}
        # Spec-ingestion bounds (F-09).
        self._spec_max_bytes = spec_max_bytes
        self._spec_translate_timeout = spec_translate_timeout
        # Bounded jittered retries for idempotent reachability/spec GETs (F-05).
        self._retry_policy = retry_policy or RetryPolicy()
        # Per-device check lock TTL. Must exceed the worst-case single-device
        # check (reachability GET + spec fetch + translation), which is
        # independent of the poll interval — otherwise a slow check lets the
        # lock expire mid-flight and a second worker checks the same device.
        # It is only a crash/hang safety net: the holder deletes the lock in
        # _check_device's finally, so a longer TTL never blocks the next cycle.
        self._lock_ttl = lock_ttl if lock_ttl is not None else max(self._interval * 2, 120)
        self._http: httpx.AsyncClient | None = None
        # Outbound mutual-TLS for reachability/spec GETs to devices (F-31). All
        # assigned devices share one config today, so one client is sufficient.
        self._tls_verify = tls_verify
        self._allow_private = allow_private
        # Per-device timestamp of the last spec poll. Tracked separately from
        # cfg.last_check (which updates every health cycle) so the much longer
        # spec_poll_interval is honoured instead of always short-circuiting.
        self._last_spec_check: dict[str, float] = {}
        # Callback set by DeviceWorker: (hostname) -> coroutine — replace pod
        self.on_spec_changed: Any = None

    def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            # SSRF-guarded: the worker re-checks every reachability/spec hop against the
            # URL policy (incl. redirects), so it can't be steered to an internal address.
            self._http = build_guarded_client(verify=self._tls_verify, allow_private=self._allow_private)
        return self._http

    async def run_forever(self, assigned: set[str]) -> None:
        """Loop until cancelled. `assigned` is a live set mutated by the worker."""
        while True:
            for hostname in list(assigned):
                try:
                    await self._check_device(hostname)
                except Exception:
                    logger.exception(f"Health loop error for {hostname}")
            # Drop spec-poll timestamps for devices no longer assigned.
            for stale in set(self._last_spec_check) - set(assigned):
                self._last_spec_check.pop(stale, None)
            await asyncio.sleep(jittered(self._interval))  # F-61: de-sync worker health loops

    async def _check_device(self, hostname: str) -> None:
        lock_key = f"health_lock:{hostname}"
        acquired = await self._r.set(lock_key, self._worker_id, nx=True, ex=self._lock_ttl)
        if not acquired:
            return  # another worker is handling this device

        try:
            cfg = await self._backend.get_device(hostname)
            if cfg is None:
                return

            # Reachability check
            reachable = await self._check_reachability(cfg.base_url)
            await self._backend.update_device_fields(hostname, reachable=reachable, last_check=time.time())

            if not reachable:
                if cfg.pod_active:
                    await self._backend.update_device_fields(hostname, pod_active=False)
                    await self._backend.publish_assignment("unassign", hostname)
                return

            # Spec polling — throttled by its own timestamp, not cfg.last_check
            # (which is rewritten every cycle above and would always short-circuit).
            now = time.time()
            last_spec = self._last_spec_check.get(hostname)
            if last_spec is None:
                # First sighting: the spec was just fetched at pod spawn, so
                # defer the first poll by a full interval rather than re-fetching.
                self._last_spec_check[hostname] = now
                return
            if now - last_spec < self._spec_poll_interval:
                return
            self._last_spec_check[hostname] = now
            spec = await self._fetch_spec(cfg)
            if spec is None:
                return

            new_hash = hashlib.sha256(str(spec).encode()).hexdigest()[:16]
            if cfg.spec_hash and new_hash != cfg.spec_hash:
                logger.info(f"Spec changed for {hostname}: {cfg.spec_hash} → {new_hash}")
                # Store new manifest in Redis
                try:
                    manifest_obj = await run_translation(
                        _spec_executor,
                        partial(_translate_spec_sync, spec, hostname),
                        timeout=self._spec_translate_timeout,
                        hostname=hostname,
                    )
                except (SpecTooLargeError, ValueError) as exc:
                    logger.warning(f"Spec for {hostname} rejected on update: {exc} (F-09)")
                    return
                manifest_dict = _manifest_to_dict(manifest_obj)
                # Governance: diff the new tool set against the manifest currently
                # in Redis and record what changed / whether it was breaking, then
                # bump the client-pollable revision (F-41).
                old_manifest = await self._backend.get_manifest(hostname)
                old_tools = (old_manifest or {}).get("tools", [])
                diff = record_tool_change(hostname, old_tools, manifest_dict.get("tools", []))
                await self._backend.set_manifest(hostname, manifest_dict, ttl=self._spec_cache_ttl)
                fields: dict[str, Any] = {"spec_hash": new_hash}
                if not diff.empty:
                    fields["tools_revision"] = (cfg.tools_revision or 0) + 1
                await self._backend.update_device_fields(hostname, **fields)
                # Signal worker to replace the pod
                if self.on_spec_changed:
                    await self.on_spec_changed(hostname)
        finally:
            await self._r.delete(lock_key)

    async def _check_reachability(self, base_url: str) -> bool:
        try:
            resp = await send_with_retry(
                lambda: self._client().get(base_url, timeout=5), method="GET", policy=self._retry_policy
            )
            return resp.status_code < 500
        except Exception:
            return False

    async def _fetch_spec(self, cfg: Any) -> dict | None:
        if cfg.spec_url:
            try:
                resp = await send_with_retry(
                    lambda: self._client().get(cfg.spec_url, timeout=10), method="GET", policy=self._retry_policy
                )
                return fetched_spec_or_none(resp, max_bytes=self._spec_max_bytes)
            except SpecTooLargeError as exc:
                logger.warning(f"Spec fetch rejected oversized spec for {cfg.spec_url}: {exc} (F-09)")
                return None
            except Exception:
                pass
            return None

        paths = self._discovery.get(
            "spec_paths",
            ["/openapi.json", "/swagger.json", "/api-docs"],
        )
        timeout = self._discovery.get("timeout", 10)
        for path in paths:
            try:
                url = cfg.base_url.rstrip("/") + path

                async def _probe(u: str = url) -> httpx.Response:
                    return await self._client().get(u, timeout=timeout)

                resp = await send_with_retry(_probe, method="GET", policy=self._retry_policy)
                spec = fetched_spec_or_none(resp, max_bytes=self._spec_max_bytes)
                if spec is not None:
                    return spec
            except SpecTooLargeError as exc:
                logger.warning(f"Spec discovery rejected oversized spec at {url}: {exc} (F-09)")
                continue
            except Exception:
                continue
        return None

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()


def _manifest_to_dict(manifest: Any) -> dict:
    """Convert McpManifest to a plain dict for Redis storage."""
    import dataclasses

    def _dc(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {k: _dc(v) for k, v in dataclasses.asdict(obj).items()}
        if isinstance(obj, list):
            return [_dc(i) for i in obj]
        return obj

    return _dc(manifest)
