# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
Device MCP Gateway FastAPI entrypoint.

registry.mode = "embedded"  (default):
  - In-process DevicePods, SQLite credential store, health loop runs here.
  - No Redis required. Single-replica only.

registry.mode = "distributed":
  - Gateway is stateless: reads device state from Redis, publishes assignments
    and tool calls to Redis Streams, routes SSE results via Redis pub/sub.
  - Requires Redis and at least one device-mcp-worker process.
  - Horizontally scalable.

This module is the app factory + lifecycle wiring only; the route handlers live
in ``device_mcp_gateway/api/`` (one module per concern) and background-task
helpers in ``device_mcp_gateway/lifecycle.py``.
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from device_mcp_gateway import API_V1_PREFIX, __version__, metrics
from device_mcp_gateway.api import admin as api_admin
from device_mcp_gateway.api import deadletter as api_deadletter
from device_mcp_gateway.api import devices as api_devices
from device_mcp_gateway.api import fleet as api_fleet
from device_mcp_gateway.api import probes as api_probes
from device_mcp_gateway.api import sse as api_sse

# Re-exported for tests and internal callers: these lived here before the router
# split and their dotted paths are part of the de-facto internal API.
from device_mcp_gateway.api.dispatch import _GATEWAY_ID, _watch_tool_call_timeout  # noqa: F401
from device_mcp_gateway.bootstrap import apply_gateway_bootstrap
from device_mcp_gateway.cfg import load_config, resolve_bind_host, resolve_mode, warn_unsafe_settings
from device_mcp_gateway.lifecycle import (  # noqa: F401  (re-exported, see above)
    _LOOP_HEARTBEAT_INTERVAL,
    _acquire_gauge_leadership,
    _count_live_workers,
    _event_loop_heartbeat,
    _refresh_device_gauges,
)
from device_mcp_gateway.logging_setup import setup_logging
from device_mcp_gateway.observability import tracing
from device_mcp_gateway.ratelimit import InMemoryRateLimiter, RedisRateLimiter, client_ip_key_func
from device_mcp_gateway.rbac import authenticate_request, build_authenticator
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import MemoryRegistryBackend, RedisRegistryBackend


class _BodyTooLarge(Exception):
    """Raised by the body-size limiter when the streamed body exceeds the cap."""


class _BodySizeLimitMiddleware:
    """Pure-ASGI request-body cap that can't be bypassed by a chunked transfer or a
    missing/understated Content-Length (F-35).

    A declared Content-Length over the cap is rejected up front; otherwise the actual
    body bytes are tallied as they stream in (covering chunked encoding and a spoofed
    low Content-Length), and the request is rejected the moment the cap is crossed —
    before the whole body is buffered into memory.
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    return await self._reject(send, 400, "Invalid Content-Length header")
                if declared > self.max_bytes:
                    return await self._reject(send, 413, self._too_large_msg())
                break

        total = 0

        async def counting_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        started = False

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLarge:
            if started:
                raise  # response already begun — can't replace it
            await self._reject(send, 413, self._too_large_msg())

    def _too_large_msg(self) -> str:
        return f"Request body exceeds the {self.max_bytes // 1024} KB limit"

    async def _reject(self, send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_app(override_config: dict | None = None) -> FastAPI:
    """Application factory. Pass override_config to skip file I/O (useful in tests)."""
    cfg = override_config if override_config is not None else load_config()
    _mode = resolve_mode(cfg)

    _log_cfg = cfg.get("logging", {})
    setup_logging(
        level=_log_cfg.get("level", "INFO"),
        log_file=_log_cfg.get("file", "logs/gateway.log"),
        max_size_mb=_log_cfg.get("max_size", 50),
        backup_count=_log_cfg.get("backup_count", 5),
        json_logs=_log_cfg.get("json_logs", True),
        audit_file=_log_cfg.get("audit_file", "logs/audit.log"),
        audit_retention=_log_cfg.get("audit_retention", "90 days"),
        audit_enabled=_log_cfg.get("audit_enabled", True),
    )

    # LITE first-run bootstrap: when MCP_API_KEY_FILE is set, self-provision an admin key
    # (reading or generating + persisting it) before auth is built, so a home box requires a
    # token without hand-config. No-op otherwise, so enterprise key resolution is unchanged.
    apply_gateway_bootstrap(cfg)
    _gateway_cfg = cfg.get("gateway", {})
    _authenticator = build_authenticator(cfg)

    try:
        _codec = CredentialCodec.from_config(cfg)
    except ValueError as exc:
        raise RuntimeError(f"Invalid MCP_SECRET_KEY / gateway.secret_key(s): {exc}") from exc

    _allow_plaintext = bool(_gateway_cfg.get("allow_plaintext_credentials", False))
    if _codec.enabled:
        # multi_key => a rotation window is active (new key primary, old key(s) still
        # able to decrypt). Run `device-mcp-rotate-secrets` then retire the old key (F-34).
        logger.info(f"Credential encryption enabled (key rotation in progress: {_codec.multi_key})")
    elif _mode == "distributed" and not _allow_plaintext:
        # Distributed mode persists credentials to Redis; refuse to run without a
        # key so secrets never land there in plaintext. Set gateway.
        # allow_plaintext_credentials: true to override (not recommended).
        raise RuntimeError(
            "Refusing to start in distributed mode without MCP_SECRET_KEY: device "
            "credentials would be written to Redis in plaintext. Set a Fernet key "
            "(MCP_SECRET_KEY) or, to override, set gateway.allow_plaintext_credentials: true. "
            'Generate a key: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    else:
        logger.warning(
            "gateway.secret_key is not set — OAuth2 client_secret and API key credentials "
            "will be stored as plaintext. Set MCP_SECRET_KEY to a Fernet key. "
            'Generate one: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )

    # Auth fail-open gate (Tier-0 F-23): distributed mode must not run with auth disabled —
    # no keys means every request is served as ANONYMOUS with full access. build_authenticator
    # already warns in embedded/local-dev; here we hard-fail the production (distributed) path.
    if _mode == "distributed" and not _authenticator.enabled and not _gateway_cfg.get("allow_anonymous", False):
        raise RuntimeError(
            "Refusing to start in distributed mode with authentication disabled: no API keys are "
            "configured, so every request would be served as ANONYMOUS with full access. Configure at "
            "least one key (MCP_GATEWAY_API_KEY / MCP_ADMIN_KEY / gateway.rbac) or, for a trusted local "
            "network only, set gateway.allow_anonymous: true to override."
        )

    # Redis control-plane authn gate (Tier-0 F-24): distributed mode keeps all shared state in
    # Redis; refuse an unauthenticated Redis (no password) unless redis.allow_insecure is set.
    if _mode == "distributed":
        from device_mcp_gateway.shared.redis_client import assert_redis_secure

        assert_redis_secure(cfg)

    # Surface permissive-by-default postures loudly at startup (Tier-1 F-53): open auth,
    # wildcard CORS, bind-all + no auth. Non-fatal — the hard refusals are the Tier-0 gates.
    warn_unsafe_settings(cfg, _mode, _authenticator.enabled)

    # ---------------------------------------------------------------------------
    # Synchronous pre-lifespan setup — state set here is available even when
    # the lifespan has not yet fired (e.g. bare TestClient without context mgr).
    # ---------------------------------------------------------------------------

    _app = FastAPI(title="Device MCP Gateway", version=__version__)
    # Configure optional OTel tracing once at startup (no-op unless tracing.enabled
    # and the [otel] extra is installed). F-14.
    tracing.init_tracing(cfg, "mcp-gateway")
    _app.state.config = cfg
    _app.state.authenticator = _authenticator
    _app.state.mode = _mode
    _app.state.redis = None
    _app.state.pubsub_redis = None
    _app.state.session_router = None
    # Event-loop liveness tick (F-17). Seeded now so /livez works before the lifespan
    # heartbeat task starts (e.g. a bare TestClient); refreshed every second once up.
    _app.state.loop_heartbeat = time.monotonic()
    # Strong refs to fire-and-forget timeout watchers so they aren't GC'd.
    _app.state.bg_tasks = set()
    # Embedded-mode session→owner map for principal↔session binding (F-37). In
    # distributed mode the owner lives on the Redis session hash instead, so the
    # binding survives across gateway replicas.
    _app.state.session_owners = {}
    # Embedded-mode fleet sessions: session_id -> SseTransport. Distributed mode
    # persists fleet session state in Redis instead of this in-process dict.
    _app.state.fleet_transports = {}
    # Short-TTL cache for the UI read aggregate (SRE O4) so a polling dashboard
    # doesn't trigger a fresh list_devices() on every request. Per-replica; ETag is
    # a content hash so it's stable across replicas.
    _app.state.overview_cache = {"ts": 0.0, "etag": "", "body": None}

    # --- Rate limiting (async; per-client-IP) ---
    # Key function honours X-Forwarded-For only behind a trusted proxy.
    _trust_proxy = bool(_gateway_cfg.get("trust_proxy_headers", False))
    _app.state.rate_limit_key = client_ip_key_func(_trust_proxy)
    # Default to in-memory; distributed mode swaps in the Redis-backed limiter
    # (shared across replicas) once Redis connects in the lifespan.
    _app.state.rate_limiter = InMemoryRateLimiter()

    # --- CORS (opt-in; configure cors.allowed_origins in config.yaml) ---
    _allowed_origins = cfg.get("cors", {}).get("allowed_origins", [])
    if _allowed_origins:
        _app.add_middleware(
            CORSMiddleware,
            allow_origins=_allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    if _mode == "embedded":
        from device_mcp_gateway.storage.sqlite_store import SqliteDeviceStore

        _storage_cfg = cfg.get("storage", {})
        _db_path = _storage_cfg.get("db_path", "./data/devices.db")
        _store = SqliteDeviceStore(db_path=_db_path, codec=_codec)
        _backend = MemoryRegistryBackend()
        _registry = Registry(
            config={
                **cfg.get("registry", {}),
                "discovery": cfg.get("discovery", {}),
                "transport": cfg.get("transport", {}),
                "security": cfg.get("security", {}),
                "mode": "embedded",
            },
            backend=_backend,
            store=_store,
            codec=_codec,
        )
        _app.state.registry = _registry
        _app.state.store = _store
    else:
        # Distributed mode: registry created in lifespan after Redis connects.
        # Set a None placeholder so attribute access doesn't crash before lifespan.
        _app.state.registry = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info(f"Device MCP Gateway starting up (mode={_mode})")

        # Event-loop liveness ticker — backs /livez (F-17). Runs in every mode.
        loop_hb_task = asyncio.create_task(_event_loop_heartbeat(app))

        if _mode == "distributed":
            from device_mcp_gateway.shared.redis_client import create_redis
            from device_mcp_gateway.shared.session_router import SessionRouter

            redis_client = await create_redis(cfg)
            # Dedicated client/pool for SSE pub/sub: one connection per open
            # stream, so it must be sized above the command pool (F3).
            _pubsub_max = cfg.get("redis", {}).get("pubsub_max_connections", 1000)
            pubsub_client = await create_redis(cfg, max_connections=_pubsub_max)
            backend = RedisRegistryBackend(redis_client)
            await backend.initialize()
            registry = Registry(
                config={**cfg.get("registry", {}), "security": cfg.get("security", {}), "mode": "distributed"},
                backend=backend,
                codec=_codec,
            )
            app.state.redis = redis_client
            app.state.pubsub_redis = pubsub_client
            app.state.session_router = SessionRouter(redis_client, pubsub_client)
            app.state.registry = registry
            # Shared, async rate limiter across gateway replicas.
            app.state.rate_limiter = RedisRateLimiter(redis_client)
            logger.info("Rate limiter using shared Redis storage")
        else:
            await app.state.store.initialize()
            registry = app.state.registry
            await registry.load_persisted_devices()
            health_task = asyncio.create_task(registry.start_health_loop())

        # --- Metrics (dedicated port + gauge refresher) ---
        gauge_task = None
        if metrics.metrics_enabled(cfg):
            metrics.start_metrics_server(metrics.metrics_port(cfg), auth_token=metrics.metrics_token(cfg))
            _refresh = cfg.get("metrics", {}).get("gauge_refresh_interval", 15)
            gauge_task = asyncio.create_task(_refresh_device_gauges(app, _refresh))

        try:
            yield
        finally:
            loop_hb_task.cancel()
            with suppress(asyncio.CancelledError):
                await loop_hb_task
            if gauge_task is not None:
                gauge_task.cancel()
                with suppress(asyncio.CancelledError):
                    await gauge_task
            if _mode == "embedded":
                health_task.cancel()
                with suppress(asyncio.CancelledError):
                    await health_task
                await app.state.registry.shutdown()
            else:
                if app.state.redis:
                    await app.state.redis.aclose()
                if app.state.pubsub_redis:
                    await app.state.pubsub_redis.aclose()

    _app.router.lifespan_context = lifespan

    _max_body_bytes: int = cfg.get("gateway", {}).get("max_body_bytes", 1_048_576)

    # --- Middleware ---

    # Body-size cap (F-35): pure-ASGI so a chunked / missing / understated
    # Content-Length can't slip an oversized body past a header-only check.
    _app.add_middleware(_BodySizeLimitMiddleware, max_bytes=_max_body_bytes)

    @_app.middleware("http")
    async def log_requests(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = (time.perf_counter() - start) * 1000
        # Attribute the access log to the resolved principal (F-56). The auth dependency
        # runs during call_next, so request.state.principal is set by now for protected
        # routes (unauthenticated/public routes log subject="-").
        _principal = getattr(request.state, "principal", None)
        logger.bind(
            subject=_principal.subject if _principal else "-",
            auth_method=_principal.auth_method if _principal else "-",
            rid=request_id,
        ).info(f"{request.method} {request.url.path} -> {response.status_code} ({elapsed:.1f}ms) rid={request_id}")
        # Prometheus: label with the route *template* (low cardinality), set after
        # routing has populated scope["endpoint"].
        route = metrics.route_template(request)
        metrics.http_requests_total.labels(method=request.method, route=route, status=str(response.status_code)).inc()
        metrics.http_request_duration_seconds.labels(method=request.method, route=route).observe(elapsed / 1000.0)
        response.headers["X-Request-Id"] = request_id
        return response

    # --- Routes ---

    # Unauthenticated operational probes (/health, /livez, /readyz) — unversioned.
    _app.include_router(api_probes.router)

    # Router-level: authenticate every protected request to a Principal. Each route
    # module then authorizes on specific scopes via require_scope(...).
    protected = APIRouter(dependencies=[Depends(authenticate_request)])
    protected.include_router(api_devices.router)
    protected.include_router(api_deadletter.router)
    protected.include_router(api_sse.router)
    protected.include_router(api_fleet.router)
    protected.include_router(api_admin.router)

    # Version the entire management API under /v1 (e.g. /v1/devices). Probes
    # (/health, /livez, /readyz) and the Prometheus scrape endpoint stay unversioned.
    _app.include_router(protected, prefix=API_V1_PREFIX)
    return _app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    _cfg = app.state.config
    host = resolve_bind_host(_cfg)
    port = _cfg.get("server", {}).get("port", 8000)
    logger.info(f"Starting uvicorn on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level=_cfg.get("logging", {}).get("level", "INFO").lower())
