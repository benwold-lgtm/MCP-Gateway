# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Device Worker — distributed mode pod host.

Each worker process:
  1. Joins the Redis Streams consumer group on device:assignments
  2. Spawns/kills DevicePod instances for assigned devices
  3. Runs a per-device tool-call consumer loop (device:{hostname}:calls stream)
  4. Runs a health loop (WorkerHealthLoop) for assigned devices
  5. Publishes tool-call results to session:{session_id}:results pub/sub

A worker registers itself in Redis with a heartbeat key (TTL = 2 × health_interval).
If the heartbeat expires, the gateway and other workers can detect the failure and
republish pending assignments via XAUTOCLAIM.
"""

from __future__ import annotations

import asyncio
import json
import signal
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Any

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.pods.device_pod import DevicePod
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import AbstractRegistryBackend
from device_mcp_gateway.worker.health import WorkerHealthLoop, _manifest_to_dict

_ASSIGNMENTS_STREAM = "device:assignments"
_WORKER_GROUP = "workers"
_HEARTBEAT_INTERVAL = 10  # seconds

_spec_executor = ProcessPoolExecutor(max_workers=2)


def _translate_spec_sync(spec: dict, hostname: str) -> Any:
    from device_mcp_gateway.core.translator import SpecTranslator

    return SpecTranslator().translate(spec, hostname)


def _auth_from_config(auth_type: str | None, auth_config_str: str | None) -> AbstractAuth | None:
    if not auth_type or not auth_config_str:
        return None
    try:
        cfg = json.loads(auth_config_str)
    except (json.JSONDecodeError, TypeError):
        return None
    from device_mcp_gateway.auth.api_key import ApiKeyAuth
    from device_mcp_gateway.auth.oauth2 import OAuth2Auth

    if auth_type == "api_key":
        return ApiKeyAuth.from_dict(cfg)
    if auth_type == "oauth2":
        return OAuth2Auth.from_dict(cfg)
    return None


class DeviceWorker:
    """Runs DevicePod instances for assigned devices and routes tool calls."""

    def __init__(
        self,
        worker_id: str,
        config: dict[str, Any],
        redis_client: Any,
        codec: CredentialCodec | None = None,
    ) -> None:
        self._id = worker_id
        self._config = config
        self._r = redis_client
        self._codec = codec or CredentialCodec(None)
        self._backend: AbstractRegistryBackend | None = None

        self._pods: dict[str, DevicePod] = {}
        self._assigned: set[str] = set()
        self._call_tasks: dict[str, asyncio.Task] = {}
        self._stop_event = asyncio.Event()

        self._keep_alive = config.get("transport", {}).get("sse", {}).get("keep_alive_interval", 30)
        # Device-claim lease TTL (RC-6). Outlives the heartbeat interval so a
        # claim refreshed each heartbeat never lapses while the pod runs, but
        # expires soon after a worker dies so another worker can take over.
        _hc = config.get("registry", {}).get("health_check_interval", 30)
        self._claim_ttl = max(_hc * 2, 60)
        # TTL for the per-call "result seen" marker the gateway's timeout watcher
        # checks (F6). Outlives the tool-call timeout so the watcher always sees it.
        self._result_marker_ttl = max(config.get("registry", {}).get("tool_call_timeout", 30) * 2, 60)
        # _health is initialised in run() after the backend is available
        self._health: WorkerHealthLoop | None = None

    async def run(self, backend: AbstractRegistryBackend) -> None:
        """Main entry point. Runs until SIGTERM/SIGINT or stop() is called."""
        self._backend = backend
        _reg_cfg = self._config.get("registry", {})
        self._health = WorkerHealthLoop(
            worker_id=self._id,
            backend=backend,
            redis_client=self._r,
            interval=_reg_cfg.get("health_check_interval", 30),
            spec_poll_interval=_reg_cfg.get("spec_poll_interval", 300),
            spec_cache_ttl=_reg_cfg.get("spec_cache_ttl", 3600),
            discovery_cfg=self._config.get("discovery", {}),
            lock_ttl=_reg_cfg.get("health_lock_ttl"),
        )
        self._health.on_spec_changed = self._replace_pod
        await backend.initialize()

        # Register worker
        await self._r.sadd("workers:active", self._id)
        logger.info(f"Worker {self._id} started")

        # Recover any devices previously assigned to this worker
        await self._recover_assigned()

        loop = asyncio.get_event_loop()
        # Handle graceful shutdown
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
            except (NotImplementedError, RuntimeError):
                pass  # Windows / some test runners

        tasks = [
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._consume_assignments(), name="assignments"),
            asyncio.create_task(self._health.run_forever(self._assigned), name="health"),  # type: ignore[union-attr]
            asyncio.create_task(self._metrics_loop(), name="metrics"),
        ]
        try:
            await self._stop_event.wait()
        finally:
            for t in tasks:
                t.cancel()
            for t in list(self._call_tasks.values()):
                t.cancel()
            await asyncio.gather(*tasks, *self._call_tasks.values(), return_exceptions=True)
            await self._shutdown_pods()
            await self._r.srem("workers:active", self._id)
            await self._health.close()
            logger.info(f"Worker {self._id} shut down")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        ttl = self._config.get("registry", {}).get("health_check_interval", 30) * 2
        key = f"worker:{self._id}:heartbeat"
        while not self._stop_event.is_set():
            await self._r.set(key, str(time.time()), ex=ttl)
            await self._refresh_claims()  # keep device-claim leases alive (RC-6)
            await asyncio.sleep(_HEARTBEAT_INTERVAL)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    async def _metrics_loop(self) -> None:
        """Refresh worker gauges on a timer (pod count + Redis Stream lag).

        Prometheus exposition itself is served by a background HTTP server started
        in worker_main; this loop only keeps the gauge values current.
        """
        interval = self._config.get("metrics", {}).get("gauge_refresh_interval", 15)
        while not self._stop_event.is_set():
            try:
                await self._refresh_worker_metrics()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("worker metrics refresh failed")
            await asyncio.sleep(interval)

    async def _refresh_worker_metrics(self) -> None:
        metrics.worker_pods.set(len(self._pods))
        pending = 0
        for hostname in list(self._assigned):
            pending += await self._stream_pending(f"device:{hostname}:calls", f"workers-{hostname}")
        metrics.worker_pending_calls.set(pending)
        metrics.worker_assignments_lag.set(await self._stream_pending(_ASSIGNMENTS_STREAM, _WORKER_GROUP))

    async def _stream_pending(self, stream: str, group: str) -> int:
        """Count delivered-but-unacked entries for a consumer group (XPENDING summary).

        Returns 0 on any error (missing stream/group, server differences) so a
        metrics hiccup never disrupts the worker loop.
        """
        try:
            info = await self._r.xpending(stream, group)
        except Exception:
            return 0
        if isinstance(info, dict):
            return int(info.get("pending", 0) or 0)
        # Some clients return a [count, min, max, consumers] summary list.
        try:
            return int(info[0]) if info else 0
        except (TypeError, IndexError, ValueError):
            return 0

    # ------------------------------------------------------------------
    # Assignment consumer
    # ------------------------------------------------------------------

    async def _consume_assignments(self) -> None:
        while not self._stop_event.is_set():
            try:
                results = await self._r.xreadgroup(
                    _WORKER_GROUP,
                    self._id,
                    {_ASSIGNMENTS_STREAM: ">"},
                    count=10,
                    block=2000,
                )
                if not results:
                    continue
                for _stream, messages in results:
                    for msg_id, fields in messages:
                        action = fields.get("action", "")
                        hostname = fields.get("hostname", "")
                        try:
                            if action == "assign":
                                await self._spawn_pod(hostname)
                            elif action == "unassign":
                                await self._kill_pod(hostname)
                            await self._r.xack(_ASSIGNMENTS_STREAM, _WORKER_GROUP, msg_id)
                        except Exception:
                            logger.exception(f"Failed to process assignment {action} {hostname}")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Assignment consumer error; retrying in 2 s")
                await asyncio.sleep(2)

    # ------------------------------------------------------------------
    # Tool call consumer
    # ------------------------------------------------------------------

    async def _consume_calls(self, hostname: str) -> None:
        stream = f"device:{hostname}:calls"
        group = f"workers-{hostname}"
        # Ensure consumer group for this device's call stream
        try:
            await self._r.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                logger.warning(f"xgroup_create {stream}: {exc}")

        while not self._stop_event.is_set() and hostname in self._assigned:
            try:
                results = await self._r.xreadgroup(
                    group,
                    self._id,
                    {stream: ">"},
                    count=5,
                    block=2000,
                )
                if not results:
                    continue
                for _s, messages in results:
                    for msg_id, fields in messages:
                        asyncio.create_task(self._dispatch_call(hostname, stream, group, msg_id, fields))
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception(f"Call consumer error for {hostname}; retrying")
                await asyncio.sleep(1)

    async def _dispatch_call(self, hostname: str, stream: str, group: str, msg_id: str, fields: dict) -> None:
        session_id = fields.get("session_id", "")
        request_id = fields.get("request_id", "")
        try:
            message = json.loads(fields.get("message", "{}"))
            pod = self._pods.get(hostname)
            if pod is None:
                logger.warning(f"No pod for {hostname}, discarding call {msg_id}")
                return
            _method = message.get("method", "?") if isinstance(message, dict) else "?"
            _t = time.perf_counter()
            result = await pod.call_tool(message)
            _dur = time.perf_counter() - _t
            # Distributed-mode tool calls execute here on the worker; record where
            # the work actually happens (the gateway only enqueues).
            if result is None:
                _status = "noresult"  # notification — no JSON-RPC response expected
            elif isinstance(result, dict) and "error" in result:
                _status = "error"
            else:
                _status = "ok"
            metrics.tool_calls_total.labels(hostname=hostname, method=_method, status=_status).inc()
            metrics.tool_call_duration_seconds.labels(hostname=hostname).observe(_dur)
            if result is not None:
                await self._r.publish(f"session:{session_id}:results", json.dumps(result))
            # Mark the call as handled so the gateway's timeout watcher (F6)
            # stands down even when the result reached a different gateway replica.
            if request_id:
                await self._r.set(f"result:{request_id}", "1", ex=self._result_marker_ttl)
        except Exception:
            logger.exception(f"Tool call dispatch error for {hostname} session {session_id}")
        finally:
            await self._r.xack(stream, group, msg_id)

    # ------------------------------------------------------------------
    # Pod lifecycle
    # ------------------------------------------------------------------

    async def _acquire_claim(self, hostname: str) -> bool:
        """Atomically claim a device before spawning so two workers can't both
        run a pod for it (RC-6). The local ``_assigned`` set isn't enough — it's
        per-worker — so a pending-assignment reclaim could otherwise hand the
        same device to two workers. Returns True if this worker holds the claim.
        """
        key = f"claim:{hostname}"
        if await self._r.set(key, self._id, nx=True, ex=self._claim_ttl):
            return True
        # Key already exists — only proceed if we already own it, which happens
        # on pod replacement and on restart recovery (worker_id is stable).
        return (await self._r.get(key)) == self._id

    async def _release_claim(self, hostname: str) -> None:
        """Release this worker's claim on a device.

        Owner-checked get-then-delete (this fakeredis build has no EVAL, so no
        Lua CAS). It is only ever called for a device we actively own and keep
        refreshed via the heartbeat, so the non-atomic window — our claim
        expiring and being re-taken between the get and the delete — is not
        reachable in practice.
        """
        key = f"claim:{hostname}"
        if (await self._r.get(key)) == self._id:
            await self._r.delete(key)

    async def _refresh_claims(self) -> None:
        """Extend the lease on every owned device claim (called per heartbeat)."""
        for hostname in list(self._assigned):
            await self._r.expire(f"claim:{hostname}", self._claim_ttl)

    def _decrypt_auth(self, hostname: str, auth_config_str: str | None) -> str | None:
        """Decrypt a stored credential blob from Redis (distributed mode).

        On failure (key mismatch / rotation) the pod loads without credentials
        and the error is logged loudly, rather than silently treating ciphertext
        as plaintext.
        """
        if not auth_config_str or not self._codec.enabled:
            return auth_config_str
        try:
            return self._codec.decrypt(auth_config_str)
        except Exception:
            logger.error(
                f"Failed to decrypt credentials for {hostname} — key may have rotated; "
                "pod will load without credentials"
            )
            return None

    async def _spawn_pod(self, hostname: str) -> None:
        if hostname in self._assigned:
            logger.debug(f"Already assigned: {hostname}")
            return
        if not await self._acquire_claim(hostname):
            logger.info(f"Device {hostname} is claimed by another worker; skipping spawn")
            return
        assert self._backend is not None, "backend not initialised — call run() first"
        cfg = await self._backend.get_device(hostname)
        if cfg is None:
            logger.warning(f"No config for device {hostname}, cannot spawn pod")
            await self._release_claim(hostname)
            return

        # Fetch or build manifest
        manifest_dict = await self._backend.get_manifest(hostname)
        if manifest_dict is None:
            spec = await self._fetch_spec(cfg)
            if spec is None:
                err = f"No spec available for {hostname}"
                logger.warning(err)
                await self._backend.update_device_fields(hostname, spawn_error=err, pod_active=False)
                await self._release_claim(hostname)
                return
            loop = asyncio.get_event_loop()
            manifest_obj = await loop.run_in_executor(_spec_executor, partial(_translate_spec_sync, spec, hostname))
            manifest_dict = _manifest_to_dict(manifest_obj)
            ttl = self._config.get("registry", {}).get("spec_cache_ttl", 3600)
            await self._backend.set_manifest(hostname, manifest_dict, ttl=ttl)
        else:
            manifest_obj = _dict_to_manifest(manifest_dict)

        auth = _auth_from_config(cfg.auth_type, self._decrypt_auth(hostname, cfg.auth_config))
        pod = DevicePod(
            hostname=hostname,
            manifest=manifest_obj,
            transport=cfg.transport,
            auth=auth,
            base_url=cfg.base_url,
            rate_limit_rps=cfg.rate_limit_rps,
            keep_alive_interval=self._keep_alive,
        )
        await pod.start(with_sse=False)  # distributed mode: no in-process SSE transport
        self._pods[hostname] = pod
        self._assigned.add(hostname)
        await self._backend.update_device_fields(hostname, pod_active=True, worker_id=self._id, spawn_error=None)
        await self._r.sadd(f"worker:{self._id}:devices", hostname)

        # Start call consumer task for this device
        task = asyncio.create_task(self._consume_calls(hostname), name=f"calls-{hostname}")
        self._call_tasks[hostname] = task
        logger.info(f"Pod spawned for {hostname} by worker {self._id}")

    async def _kill_pod(self, hostname: str) -> None:
        if hostname not in self._assigned:
            return
        pod = self._pods.pop(hostname, None)
        if pod:
            pod.stop()
            await pod.aclose()
        self._assigned.discard(hostname)
        task = self._call_tasks.pop(hostname, None)
        if task and not task.done():
            task.cancel()
        if self._backend:
            await self._backend.update_device_fields(hostname, pod_active=False, worker_id=None)
        await self._r.srem(f"worker:{self._id}:devices", hostname)
        await self._release_claim(hostname)
        logger.info(f"Pod killed for {hostname} by worker {self._id}")

    async def _replace_pod(self, hostname: str) -> None:
        """Restart pod after a spec change."""
        await self._kill_pod(hostname)
        await self._spawn_pod(hostname)

    async def _shutdown_pods(self) -> None:
        for hostname in list(self._assigned):
            await self._kill_pod(hostname)

    # ------------------------------------------------------------------
    # Recovery on restart
    # ------------------------------------------------------------------

    async def _recover_assigned(self) -> None:
        """Re-spawn pods for devices this worker owned before a restart."""
        devices = await self._r.smembers(f"worker:{self._id}:devices")
        if not devices:
            return
        logger.info(f"Recovering {len(devices)} previously assigned device(s)")
        for hostname in devices:
            try:
                await self._spawn_pod(hostname)
            except Exception:
                logger.exception(f"Recovery failed for {hostname}")

    # ------------------------------------------------------------------
    # Spec fetching
    # ------------------------------------------------------------------

    async def _fetch_spec(self, cfg: Any) -> dict | None:
        import httpx

        discovery = self._config.get("discovery", {})
        async with httpx.AsyncClient(follow_redirects=True) as client:
            if cfg.spec_url:
                try:
                    resp = await client.get(cfg.spec_url, timeout=10)
                    if resp.status_code == 200:
                        return resp.json()
                except Exception:
                    pass
                return None
            paths = discovery.get("spec_paths", ["/openapi.json", "/swagger.json", "/api-docs"])
            timeout = discovery.get("timeout", 10)
            for path in paths:
                try:
                    resp = await client.get(cfg.base_url.rstrip("/") + path, timeout=timeout)
                    if resp.status_code == 200:
                        return resp.json()
                except Exception:
                    continue
        return None


# ---------------------------------------------------------------------------
# Manifest dict ↔ McpManifest conversion helpers
# ---------------------------------------------------------------------------


def _dict_to_manifest(d: dict) -> Any:
    """Reconstruct an McpManifest from a plain dict (Redis round-trip)."""
    from device_mcp_gateway.core.translator import McpManifest, McpPrompt, McpResource, McpTool

    return McpManifest(
        server_name=d.get("server_name", ""),
        server_version=d.get("server_version", "0.0.0"),
        hostname=d.get("hostname", ""),
        tools=[
            McpTool(
                name=t["name"],
                description=t.get("description", ""),
                schema=t.get("schema", {}),
                method=t.get("method", "GET"),
                path=t.get("path", "/"),
                tags=t.get("tags", []),
                param_locations=t.get("param_locations", {}),
            )
            for t in d.get("tools", [])
        ],
        resources=[
            McpResource(
                uri=r["uri"],
                name=r.get("name", ""),
                description=r.get("description", ""),
                mime_type=r.get("mime_type", "application/json"),
            )
            for r in d.get("resources", [])
        ],
        prompts=[
            McpPrompt(
                name=p["name"],
                description=p.get("description", ""),
                template=p.get("template", ""),
                arguments=p.get("arguments", []),
            )
            for p in d.get("prompts", [])
        ],
        metadata=d.get("metadata", {}),
    )
