# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
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

from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.pods.device_pod import DevicePod
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
        fernet: Any = None,
    ) -> None:
        self._id = worker_id
        self._config = config
        self._r = redis_client
        self._fernet = fernet
        self._backend: AbstractRegistryBackend | None = None

        self._pods: dict[str, DevicePod] = {}
        self._assigned: set[str] = set()
        self._call_tasks: dict[str, asyncio.Task] = {}
        self._stop_event = asyncio.Event()

        self._keep_alive = config.get("transport", {}).get("sse", {}).get("keep_alive_interval", 30)
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
            await self._r.setex(key, ttl, str(time.time()))
            await asyncio.sleep(_HEARTBEAT_INTERVAL)

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
        try:
            message = json.loads(fields.get("message", "{}"))
            pod = self._pods.get(hostname)
            if pod is None:
                logger.warning(f"No pod for {hostname}, discarding call {msg_id}")
                return
            result = await pod.call_tool(message)
            if result is not None:
                await self._r.publish(f"session:{session_id}:results", json.dumps(result))
        except Exception:
            logger.exception(f"Tool call dispatch error for {hostname} session {session_id}")
        finally:
            await self._r.xack(stream, group, msg_id)

    # ------------------------------------------------------------------
    # Pod lifecycle
    # ------------------------------------------------------------------

    async def _spawn_pod(self, hostname: str) -> None:
        if hostname in self._assigned:
            logger.debug(f"Already assigned: {hostname}")
            return
        assert self._backend is not None, "backend not initialised — call run() first"
        cfg = await self._backend.get_device(hostname)
        if cfg is None:
            logger.warning(f"No config for device {hostname}, cannot spawn pod")
            return

        # Fetch or build manifest
        manifest_dict = await self._backend.get_manifest(hostname)
        if manifest_dict is None:
            spec = await self._fetch_spec(cfg)
            if spec is None:
                err = f"No spec available for {hostname}"
                logger.warning(err)
                await self._backend.update_device_fields(hostname, spawn_error=err, pod_active=False)
                return
            loop = asyncio.get_event_loop()
            manifest_obj = await loop.run_in_executor(_spec_executor, partial(_translate_spec_sync, spec, hostname))
            manifest_dict = _manifest_to_dict(manifest_obj)
            ttl = self._config.get("registry", {}).get("spec_cache_ttl", 3600)
            await self._backend.set_manifest(hostname, manifest_dict, ttl=ttl)
        else:
            manifest_obj = _dict_to_manifest(manifest_dict)

        auth = _auth_from_config(cfg.auth_type, cfg.auth_config)
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
        self._assigned.discard(hostname)
        task = self._call_tasks.pop(hostname, None)
        if task and not task.done():
            task.cancel()
        if self._backend:
            await self._backend.update_device_fields(hostname, pod_active=False, worker_id=None)
        await self._r.srem(f"worker:{self._id}:devices", hostname)
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
