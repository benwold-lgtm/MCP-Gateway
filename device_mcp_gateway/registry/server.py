# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
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
import time
from typing import Any

from loguru import logger

from device_mcp_gateway.audit import redact_url
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.core.backoff import RetryPolicy, jittered, send_with_retry
from device_mcp_gateway.core.manifest_diff import record_tool_change
from device_mcp_gateway.registry.models import DeviceProfile
from device_mcp_gateway.registry.pod_supervisor import PodSupervisor
from device_mcp_gateway.registry.spec_service import SpecService
from device_mcp_gateway.security.mtls import build_verify
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import (
    AbstractRegistryBackend,
    DeviceConfig,
    MemoryRegistryBackend,
)
from device_mcp_gateway.storage.base import AbstractDeviceStore

# Re-exported for backward compatibility — DeviceProfile moved to registry.models
# during the F-12 decomposition, but importers may still reference it here.
__all__ = ["Registry", "DeviceProfile"]

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
        codec: CredentialCodec | None = None,
    ):
        self._config = config
        self._mode = config.get("mode", "embedded")
        self._backend: AbstractRegistryBackend = backend or MemoryRegistryBackend()
        self._store = store  # SQLite credential store (embedded mode only)
        # Encrypts credentials written to Redis in distributed mode.
        self._codec = codec or CredentialCodec(None)

        # Embedded-mode runtime state (not used in distributed mode)
        self._profiles: dict[str, DeviceProfile] = {}
        self._device_locks: dict[str, asyncio.Lock] = {}
        self._health_task: asyncio.Task | None = None
        self._health_interval = config.get("health_check_interval", 30)
        # Async registration (F-11): reachability probe + spec discovery + pod spawn
        # run off the POST /devices request path on a background task, so a slow or
        # unreachable device can't stall the caller. Registration waits inline up to
        # this budget so a fast/healthy device still returns ready; past the budget
        # it returns and the task finishes in the background.
        self._registration_provision_budget = config.get("registration_provision_budget", 8)
        self._provision_tasks: dict[str, asyncio.Task] = {}
        # Outbound mutual-TLS for device calls (F-31): reachability/discovery GETs
        # (here, via the SpecService client), and tool calls in the pods we spawn,
        # both present this client cert / honour this CA. True when nothing is
        # configured (default httpx behaviour).
        self._tls_verify = build_verify(config.get("security", {}).get("mtls"))
        self._health_semaphore = asyncio.Semaphore(config.get("max_concurrent_health_checks", 10))
        # Bounded jittered retries for idempotent outbound GETs — reachability, spec
        # fetch, discovery (F-05). Shared by spawned pods for their tool calls too.
        self._retry_policy = RetryPolicy.from_config({"registry": config})
        # F-12 decomposition: spec acquisition and pod lifecycle live in dedicated
        # collaborators. The Registry orchestrates them (CRUD, provisioning, health).
        self._spec_service = SpecService(
            backend=self._backend, config=config, tls_verify=self._tls_verify, retry_policy=self._retry_policy
        )
        self._pod_supervisor = PodSupervisor(
            backend=self._backend,
            config=config,
            tls_verify=self._tls_verify,
            retry_policy=self._retry_policy,
            spec_service=self._spec_service,
            profiles=self._profiles,
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _lock_for(self, hostname: str) -> asyncio.Lock:
        if hostname not in self._device_locks:
            self._device_locks[hostname] = asyncio.Lock()
        return self._device_locks[hostname]

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
        # Provision off the request path (F-11) so a slow/unreachable device or a
        # long spec discovery can't stall the POST; the fast path still returns ready.
        await self._provision_in_background(profile, wait_budget=self._registration_provision_budget)
        return profile.config

    async def replace_device(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None = None,
        auth: AbstractAuth | None = None,
        transport: str = "sse",
        rate_limit_rps: float | None = None,
        *,
        keep_auth: bool = False,
    ) -> DeviceConfig:
        """PUT semantics: kill existing pod and re-register atomically.

        ``keep_auth`` means the caller (a PUT that omitted any auth field) wants the
        stored credentials preserved. We carry the existing record through verbatim
        rather than reconstructing an ``AbstractAuth`` — in distributed mode the
        stored ``auth_config`` is Fernet ciphertext, so reconstructing it parsed the
        ciphertext as JSON, failed, and silently re-registered the device with NO
        credentials (the PUT-wipes-credentials bug).
        """
        if self._mode == "distributed":
            await self._backend.publish_assignment("unassign", hostname)
            if keep_auth:
                prev = await self._backend.get_device(hostname)
                # Pass the stored ciphertext straight through — no decrypt/re-encrypt.
                return await self._write_distributed(
                    hostname,
                    base_url,
                    spec_url,
                    prev.auth_type if prev else None,
                    prev.auth_config if prev else None,
                    transport,
                    rate_limit_rps,
                )
            return await self._register_distributed(hostname, base_url, spec_url, auth, transport, rate_limit_rps)
        async with self._lock_for(hostname):
            existing = self._profiles.get(hostname)
            if keep_auth and existing:
                # Embedded keeps the live auth object on the profile; reuse it directly.
                auth = existing.auth
            if existing:
                await self._pod_supervisor.kill(existing)
                self._spec_service.invalidate(existing.base_url)
            profile = await self._setup_device_nolock(hostname, base_url, spec_url, auth, transport, rate_limit_rps)
        # Re-provision off the request path (F-11), same as register_device.
        await self._provision_in_background(profile, wait_budget=self._registration_provision_budget)
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
                await self._pod_supervisor.kill(profile)
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
            # Single pipelined fetch instead of N get_device round-trips (F5).
            return await self._backend.get_devices(hostnames)
        return [p.config for p in self._profiles.values()]

    async def get_manifest(self, hostname: str) -> dict | None:
        return await self._backend.get_manifest(hostname)

    async def get_last_tool_change(self, hostname: str) -> dict | None:
        """The most recent recorded tool-set change for a device (F-41), or None
        if no change has been observed since registration."""
        return await self._backend.get_last_tool_change(hostname)

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
        # Encrypt credentials before they land in Redis (distributed mode).
        if auth_config_str:
            auth_config_str = self._codec.encrypt(auth_config_str)
        return await self._write_distributed(
            hostname, base_url, spec_url, auth_type, auth_config_str, transport, rate_limit_rps
        )

    async def _write_distributed(
        self,
        hostname: str,
        base_url: str,
        spec_url: str | None,
        auth_type: str | None,
        auth_config_str: str | None,
        transport: str,
        rate_limit_rps: float | None,
    ) -> DeviceConfig:
        """Persist a device record (auth_config already encrypted) and publish assign.

        Split out of ``_register_distributed`` so ``replace_device(keep_auth=True)``
        can write back the previously-stored ciphertext without round-tripping it
        through decrypt/re-encrypt or an ``AbstractAuth`` reconstruction.
        """
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

        logger.info(f"Device registered: hostname={hostname}, base_url={redact_url(base_url)}")
        return profile

    async def _provision_device(self, profile: DeviceProfile) -> None:
        """Reachability probe + spec fetch + pod spawn for a just-registered device.

        Runs off the registration request path (F-11). Holds the per-device lock so
        it serialises with a concurrent replace/deregister, and bails if the profile
        was superseded while it waited for the lock.
        """
        async with self._lock_for(profile.hostname):
            if self._profiles.get(profile.hostname) is not profile:
                return  # replaced/deregistered while we were queued
            try:
                reachable = await self.check_reachability(profile)
                if reachable:
                    await self._spec_service.fetch_spec(profile)
                    if profile.spec_data and not profile.pod_active:
                        await self._pod_supervisor.spawn(profile)
            except Exception as exc:
                logger.exception(f"Error during provisioning for {profile.hostname}")
                profile.config.spawn_error = str(exc)

    async def _provision_in_background(self, profile: DeviceProfile, *, wait_budget: float | None) -> None:
        """Schedule provisioning as a tracked task and optionally wait up to a budget.

        Within the budget a fast/healthy device finishes provisioning inline so the
        caller's response reflects the spawned pod; past the budget the task keeps
        running and the device becomes ready shortly after (also re-checked by the
        health loop). ``wait_budget=None`` is fire-and-forget.
        """
        hostname = profile.hostname
        task = asyncio.create_task(self._provision_device(profile))
        self._provision_tasks[hostname] = task

        def _done(t: asyncio.Task, h: str = hostname) -> None:
            if self._provision_tasks.get(h) is t:
                self._provision_tasks.pop(h, None)

        task.add_done_callback(_done)
        if wait_budget and wait_budget > 0:
            done, _pending = await asyncio.wait({task}, timeout=wait_budget)
            if not done:
                logger.info(
                    f"Device {hostname} registered; provisioning continues in background "
                    f"(exceeded {wait_budget}s budget)"
                )

    def is_provisioning(self, hostname: str) -> bool:
        """True while a background provisioning task for ``hostname`` is still running
        (embedded mode). Lets a caller surface that registration accepted the device
        but its pod isn't ready yet (F-11)."""
        task = self._provision_tasks.get(hostname)
        return task is not None and not task.done()

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
            await self._provision_device(profile)

    async def check_reachability(self, profile: DeviceProfile) -> bool:
        try:
            resp = await send_with_retry(
                lambda: self._spec_service.client().get(profile.base_url, timeout=5),
                method="GET",
                policy=self._retry_policy,
            )
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
                    spec_changed = False
                    if reachable:
                        spec_changed = await self._spec_service.fetch_spec(profile)
                    if profile.reachable and not profile.pod_active:
                        await self._pod_supervisor.spawn(profile)
                    elif not profile.reachable and profile.pod_active:
                        await self._pod_supervisor.kill(profile)
                    elif spec_changed and profile.pod_active:
                        # Spec acquisition is now side-effect-free (F-12); the
                        # pod replace that used to live inside fetch_spec happens
                        # here, where the orchestration belongs.
                        logger.info(f"Replacing pod for {profile.hostname} due to spec change")
                        old_tools = list(profile.pod.manifest.tools) if profile.pod else []
                        await self._pod_supervisor.replace(profile)
                        # Governance: record what changed in the tool set and bump
                        # the client-pollable revision (F-41).
                        new_tools = list(profile.pod.manifest.tools) if profile.pod else []
                        diff = record_tool_change(profile.hostname, old_tools, new_tools)
                        if not diff.empty:
                            profile.config.tools_revision += 1
                            await self._backend.update_device_fields(
                                profile.hostname, tools_revision=profile.config.tools_revision
                            )
                            # Persist what changed so GET /tools/diff can serve it (F-41).
                            await self._backend.set_last_tool_change(
                                profile.hostname,
                                diff.to_record(profile.config.tools_revision, time.time()),
                            )
                except Exception:
                    logger.exception(f"Health check error for {profile.hostname}")

    async def start_health_loop(self) -> None:
        """Embedded mode only. Distributed mode health is handled by workers."""
        while True:
            profiles = list(self._profiles.values())
            if profiles:
                await asyncio.gather(*[self._health_check_one(p) for p in profiles])
            await asyncio.sleep(jittered(self._health_interval))  # F-61: de-sync fleet health loops

    # ------------------------------------------------------------------
    # Embedded mode: backward-compat accessor (used by main.py routes)
    # ------------------------------------------------------------------

    def get_profile(self, hostname: str) -> DeviceProfile | None:
        """Return the local DeviceProfile (embedded mode only)."""
        return self._profiles.get(hostname)

    async def shutdown(self) -> None:
        # Stop any in-flight background provisioning before tearing down pods (F-11).
        for task in list(self._provision_tasks.values()):
            task.cancel()
        if self._provision_tasks:
            await asyncio.gather(*self._provision_tasks.values(), return_exceptions=True)
            self._provision_tasks.clear()
        for profile in self._profiles.values():
            await self._pod_supervisor.kill(profile)
        await self._spec_service.aclose()
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
