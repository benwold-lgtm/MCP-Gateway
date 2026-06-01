"""Pod Manager - lifecycle controller for all device pods."""

import asyncio
from typing import Any

from loguru import logger
from device_mcp_gateway.pods.device_pod import DevicePod


class PodManager:
    """Manages the lifecycle of all active device pods."""

    def __init__(self):
        self._pods: dict[str, DevicePod] = {}
        self._lock = asyncio.Lock()

    async def spawn(self, pod: DevicePod) -> bool:
        """Start a new pod for a device."""
        async with self._lock:
            if pod.hostname in self._pods and self._pods[pod.hostname]._running:
                logger.warning(f"Pod already running for {pod.hostname}")
                return False
            self._pods[pod.hostname] = pod
            await pod.start()
            return True

    async def stop_hardware(self, hostname: str) -> None:
        """Stop and remove a specific pod."""
        async with self._lock:
            if hostname in self._pods:
                self._pods[hostname].stop()
                del self._pods[hostname]
                logger.info(f"Pod stopped and removed for {hostname}")

    async def stop_all(self) -> None:
        """Gracefully stop every active pod."""
        async with self._lock:
            for h, p in self._pods.items():
                p.stop()
            self._pods.clear()
            logger.info("All pods stopped via PodManager")

    @property
    def active_count(self) -> int:
        return sum(1 for p in self._pods.values() if p._running)
