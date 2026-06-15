# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""PodSupervisor — embedded-mode DevicePod lifecycle (F-12).

Extracted from the Registry god-object. Owns spawning and killing in-process
DevicePods: translating a fetched spec into an MCP manifest (in a worker
process), constructing the pod with the right auth / retry / outbound-TLS, and
enforcing the per-process pod cap.

Depends on SpecService only as a fallback (fetch the spec if the profile doesn't
have it yet); it never fetches reachability or drives the health loop — that
orchestration stays in the Registry.
"""

from __future__ import annotations

import atexit
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Any

from loguru import logger

from device_mcp_gateway.core.spec_limits import DEFAULT_TRANSLATE_TIMEOUT, SpecTooLargeError, run_translation
from device_mcp_gateway.core.translator import SpecTranslator
from device_mcp_gateway.pods.device_pod import DevicePod
from device_mcp_gateway.registry.models import DeviceProfile
from device_mcp_gateway.registry.spec_service import SpecService
from device_mcp_gateway.shared.registry_backend import AbstractRegistryBackend

# Process-global translation pool, shared across Registry instances. Registered
# with atexit (not torn down per-instance) so reuse across instances is safe (RC-5).
_spec_executor = ProcessPoolExecutor(max_workers=4)


def _shutdown_spec_executor() -> None:
    """Reap the spec-translation worker processes at interpreter exit (RC-5)."""
    _spec_executor.shutdown(wait=False)


atexit.register(_shutdown_spec_executor)


def _translate_spec_sync(spec: dict, hostname: str) -> Any:
    """Run in a worker process to avoid blocking the event loop."""
    return SpecTranslator().translate(spec, hostname)


class PodSupervisor:
    """Spawns and kills embedded DevicePods for device profiles."""

    def __init__(
        self,
        *,
        backend: AbstractRegistryBackend,
        config: dict[str, Any],
        tls_verify: Any,
        retry_policy: Any,
        spec_service: SpecService,
        profiles: dict[str, DeviceProfile],
    ) -> None:
        self._backend = backend
        self._config = config
        self._tls_verify = tls_verify
        self._retry_policy = retry_policy
        self._spec_service = spec_service
        # Shared with the Registry: read-only here, to enforce the pod cap.
        self._profiles = profiles
        self._max_pods = config.get("max_concurrent_pods", 50)
        self._spec_translate_timeout = config.get("spec_translate_timeout", DEFAULT_TRANSLATE_TIMEOUT)

    async def spawn(self, profile: DeviceProfile) -> None:
        if sum(1 for p in self._profiles.values() if p.pod_active) >= self._max_pods:
            logger.warning("Max pods reached, skipping spawn")
            return
        if not profile.spec_data:
            await self._spec_service.fetch_spec(profile)
        spec = profile.spec_data
        if not spec:
            msg = f"No spec available for {profile.hostname}, cannot spawn pod"
            logger.warning(msg)
            profile.config.spawn_error = msg
            return
        try:
            mcp_manifest = await run_translation(
                _spec_executor,
                partial(_translate_spec_sync, spec, profile.hostname),
                timeout=self._spec_translate_timeout,
                hostname=profile.hostname,
            )
        except (SpecTooLargeError, ValueError) as exc:
            msg = f"Spec for {profile.hostname} rejected: {exc} (F-09)"
            logger.warning(msg)
            profile.config.spawn_error = msg
            return
        keep_alive = self._config.get("transport", {}).get("sse", {}).get("keep_alive_interval", 30)
        pod = DevicePod(
            hostname=profile.hostname,
            manifest=mcp_manifest,
            transport=profile.transport,
            auth=profile.auth,
            base_url=profile.base_url,
            rate_limit_rps=profile.rate_limit_rps,
            keep_alive_interval=keep_alive,
            retry_policy=self._retry_policy,
            tls_verify=self._tls_verify,
        )
        await pod.start()
        profile.pod = pod
        profile.config.pod_active = True
        profile.config.spawn_error = None
        await self._backend.update_device_fields(profile.hostname, pod_active=True, spawn_error=None)
        logger.info(f"Pod spawned for {profile.hostname}")

    async def kill(self, profile: DeviceProfile) -> None:
        if profile.pod and profile.pod_active:
            profile.pod.stop()
            await profile.pod.aclose()
            profile.config.pod_active = False
            await self._backend.update_device_fields(profile.hostname, pod_active=False)
            logger.info(f"Pod killed for {profile.hostname}")

    async def replace(self, profile: DeviceProfile) -> None:
        """Kill then re-spawn a pod (used on spec change)."""
        await self.kill(profile)
        await self.spawn(profile)
