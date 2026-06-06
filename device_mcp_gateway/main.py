# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
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
"""

import asyncio
import hmac
import json
import os
import re
import time
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from sse_starlette import EventSourceResponse

from device_mcp_gateway import __version__
from device_mcp_gateway.cfg import load_config, resolve_mode
from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway import metrics
from device_mcp_gateway.logging_setup import setup_logging
from device_mcp_gateway.ratelimit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    client_ip_key_func,
    rate_limit,
)
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import (
    MemoryRegistryBackend,
    RedisRegistryBackend,
)

_http_bearer = HTTPBearer(auto_error=False)

# Gateway instance ID — used to tag SSE sessions in distributed mode.
_GATEWAY_ID = os.getenv("GATEWAY_ID", str(uuid.uuid4()))


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_http_bearer),
) -> None:
    key = request.app.state.gateway_api_key
    if not key:
        request.state.auth_caller = "unauthenticated"
        return
    if credentials is None or not hmac.compare_digest(credentials.credentials, key):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Store a non-secret fingerprint for audit logs (first 8 chars of the token).
    request.state.auth_caller = f"bearer:{credentials.credentials[:8]}..."


def _parse_rate_limit(data: dict) -> float | None:
    rps = data.get("rate_limit_rps")
    if rps is None:
        return None
    try:
        rps = float(rps)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="rate_limit_rps must be a positive number")
    if rps <= 0:
        raise HTTPException(status_code=400, detail="rate_limit_rps must be a positive number")
    return rps


def _validate_transport(transport: str) -> None:
    if transport != "sse":
        raise HTTPException(
            status_code=400,
            detail=f"Transport '{transport}' is not supported in gateway mode; use 'sse'",
        )


_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$")


def _validate_hostname(hostname: str) -> None:
    if not hostname or len(hostname) > 253 or not _HOSTNAME_RE.match(hostname):
        raise HTTPException(
            status_code=400,
            detail="hostname must be 1–253 characters, start and end with a letter or digit, "
            "and contain only letters, digits, hyphens, or dots",
        )


async def _watch_tool_call_timeout(redis, session_router, session_id, request_id, msg_id, timeout):
    """Emit a JSON-RPC timeout error on the SSE stream if no worker responds.

    Cross-replica safe: the worker sets result:{request_id} in Redis when it
    handles the call, so this watcher (which may run on a different gateway
    replica than the one holding the SSE stream) checks that shared marker
    rather than observing the pub/sub channel directly (F6).
    """
    try:
        await asyncio.sleep(timeout)
        if await redis.get(f"result:{request_id}"):
            return  # worker handled it
        await session_router.publish_result(
            session_id,
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32001, "message": f"Tool call timed out after {timeout}s — no worker responded"},
            },
        )
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.warning(f"tool-call timeout watcher failed for request {request_id}")


async def _refresh_device_gauges(app: FastAPI, interval: float) -> None:
    """Periodically refresh device-fleet gauges from the registry.

    Prometheus collection is synchronous, but ``list_devices()`` is async, so we
    cannot compute these inside a collector — we poll on a timer instead.
    """
    while True:
        try:
            reg = app.state.registry
            if reg is not None:
                devices = await reg.list_devices()
                metrics.registered_devices.set(len(devices))
                metrics.active_pods.set(sum(1 for d in devices if d.pod_active))
                metrics.reachable_devices.set(sum(1 for d in devices if d.reachable))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("device gauge refresh failed")
        await asyncio.sleep(interval)


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
    )

    _gateway_cfg = cfg.get("gateway", {})
    gateway_api_key: str = os.getenv("MCP_GATEWAY_API_KEY") or _gateway_cfg.get("api_key") or ""

    try:
        _codec = CredentialCodec.from_config(cfg)
    except ValueError as exc:
        raise RuntimeError(f"Invalid MCP_SECRET_KEY / gateway.secret_key: {exc}") from exc

    _allow_plaintext = bool(_gateway_cfg.get("allow_plaintext_credentials", False))
    if _codec.enabled:
        logger.info("Credential encryption enabled")
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

    def _parse_auth(data: dict) -> AbstractAuth | None:
        auth_type = (
            data.get("auth_type") or data.get("auth", {}).get("type") or cfg.get("auth", {}).get("type", "api_key")
        )
        if auth_type == "api_key":
            api_key = data.get("auth", {}).get("api_key") or data.get("api_key")
            header_name = data.get("auth", {}).get("header_name") or cfg.get("auth", {}).get("api_key", {}).get(
                "header_name", "X-API-Key"
            )
            return ApiKeyAuth(api_key=api_key, header_name=header_name) if api_key else None
        if auth_type == "oauth2":
            auth_cfg = data.get("auth", {})
            token_endpoint = auth_cfg.get("token_endpoint") or cfg.get("auth", {}).get("oauth2", {}).get(
                "token_endpoint"
            )
            client_id = auth_cfg.get("client_id") or cfg.get("auth", {}).get("oauth2", {}).get("client_id")
            client_secret = auth_cfg.get("client_secret") or cfg.get("auth", {}).get("oauth2", {}).get("client_secret")
            scopes = auth_cfg.get("scopes") or cfg.get("auth", {}).get("oauth2", {}).get("scopes", ["read"])
            if not token_endpoint or not client_id or not client_secret:
                raise HTTPException(
                    status_code=400, detail="oauth2 requires token_endpoint, client_id, and client_secret"
                )
            return OAuth2Auth(
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
                scopes=scopes,
            )
        if auth_type == "none":
            return None
        raise HTTPException(status_code=400, detail=f"Unsupported auth_type: {auth_type}")

    # ---------------------------------------------------------------------------
    # Synchronous pre-lifespan setup — state set here is available even when
    # the lifespan has not yet fired (e.g. bare TestClient without context mgr).
    # ---------------------------------------------------------------------------

    _app = FastAPI(title="Device MCP Gateway", version=__version__)
    _app.state.config = cfg
    _app.state.gateway_api_key = gateway_api_key
    _app.state.mode = _mode
    _app.state.redis = None
    _app.state.pubsub_redis = None
    _app.state.session_router = None
    # Strong refs to fire-and-forget timeout watchers so they aren't GC'd.
    _app.state.bg_tasks = set()

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
                config={**cfg.get("registry", {}), "mode": "distributed"}, backend=backend, codec=_codec
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
            metrics.start_metrics_server(metrics.metrics_port(cfg))
            _refresh = cfg.get("metrics", {}).get("gauge_refresh_interval", 15)
            gauge_task = asyncio.create_task(_refresh_device_gauges(app, _refresh))

        try:
            yield
        finally:
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

    @_app.middleware("http")
    async def limit_body_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None and int(content_length) > _max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body exceeds the {_max_body_bytes // 1024} KB limit"},
            )
        return await call_next(request)

    @_app.middleware("http")
    async def log_requests(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code} " f"({elapsed:.1f}ms) rid={request_id}"
        )
        # Prometheus: label with the route *template* (low cardinality), set after
        # routing has populated scope["endpoint"].
        route = metrics.route_template(request)
        metrics.http_requests_total.labels(method=request.method, route=route, status=str(response.status_code)).inc()
        metrics.http_request_duration_seconds.labels(method=request.method, route=route).observe(elapsed / 1000.0)
        response.headers["X-Request-Id"] = request_id
        return response

    # --- Unauthenticated routes ---

    @_app.get("/health", dependencies=[Depends(rate_limit("300/minute", "health"))])
    async def health_check(request: Request):
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode

        devices = await reg.list_devices()
        active = sum(1 for d in devices if d.pod_active)

        return {
            "status": "healthy",
            "mode": mode,
            "active_pods": active,
            "registered_devices": len(devices),
            "version": cfg.get("server", {}).get("version", __version__),
        }

    @_app.get("/readyz", dependencies=[Depends(rate_limit("300/minute", "readyz"))])
    async def readiness_check(request: Request):
        """Deep readiness probe — checks backend infrastructure connectivity.
        K8s readiness probe target; returns 503 until the backend is reachable.
        Unlike /health, does NOT check business state (device count, pod_active).
        """
        mode = request.app.state.mode
        try:
            if mode == "distributed":
                redis = request.app.state.redis
                if redis is None:
                    return JSONResponse(
                        status_code=503,
                        content={"status": "not ready", "mode": mode, "reason": "Redis not yet connected"},
                    )
                await redis.ping()
            else:
                await request.app.state.store.health_check()
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"status": "not ready", "mode": mode, "reason": str(exc)},
            )
        return {"status": "ready", "mode": mode}

    # --- Protected routes ---

    protected = APIRouter(dependencies=[Depends(require_auth)])

    @protected.post("/devices", dependencies=[Depends(rate_limit("60/minute", "devices_post"))])
    async def register_device(request: Request):
        data = await request.json()
        reg: Registry = request.app.state.registry
        hostname = data.get("hostname")
        base_url = data.get("base_url")

        if not hostname or not base_url:
            raise HTTPException(status_code=400, detail="hostname and base_url required")
        _validate_hostname(hostname)

        existing = await reg.get_device(hostname)
        if existing:
            raise HTTPException(status_code=409, detail=f"Device '{hostname}' already registered; use PUT to update")

        auth = _parse_auth(data)
        transport = data.get("transport") or cfg.get("transport", {}).get("default", "sse")
        _validate_transport(transport)
        spec_url = data.get("spec_url")
        rate_limit_rps = _parse_rate_limit(data)

        device_cfg = await reg.register_device(
            hostname=hostname,
            base_url=base_url,
            spec_url=spec_url,
            auth=auth,
            transport=transport,
            rate_limit_rps=rate_limit_rps,
        )

        return {
            "status": "registered",
            "hostname": hostname,
            "pod_active": device_cfg.pod_active,
            "reachable": device_cfg.reachable,
            "spawn_error": device_cfg.spawn_error,
        }

    @protected.put("/devices/{hostname}")
    async def update_device(hostname: str, request: Request):
        reg: Registry = request.app.state.registry
        existing = await reg.get_device(hostname)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")

        data = await request.json()
        base_url = data.get("base_url") or existing.base_url
        spec_url = data.get("spec_url", existing.spec_url)

        _AUTH_KEYS = {"auth_type", "auth", "api_key"}
        if _AUTH_KEYS & data.keys():
            auth = _parse_auth(data)
        else:
            # Reconstruct auth from stored config
            from device_mcp_gateway.registry.server import _auth_from_record

            auth = _auth_from_record({"auth_config": existing.auth_config, "auth_type": existing.auth_type})
        transport = data.get("transport") or existing.transport
        _validate_transport(transport)
        rate_limit_rps = _parse_rate_limit(data)

        device_cfg = await reg.replace_device(
            hostname=hostname,
            base_url=base_url,
            spec_url=spec_url,
            auth=auth,
            transport=transport,
            rate_limit_rps=rate_limit_rps,
        )

        return {
            "status": "updated",
            "hostname": hostname,
            "pod_active": device_cfg.pod_active,
            "reachable": device_cfg.reachable,
            "spawn_error": device_cfg.spawn_error,
        }

    @protected.get("/devices")
    async def list_devices(request: Request):
        reg: Registry = request.app.state.registry
        devices = await reg.list_devices()
        return {
            "devices": [
                {
                    "hostname": d.hostname,
                    "base_url": d.base_url,
                    "reachable": d.reachable,
                    "pod_active": d.pod_active,
                    "last_check": d.last_check,
                    "transport": d.transport,
                    "rate_limit_rps": d.rate_limit_rps,
                }
                for d in devices
            ]
        }

    @protected.get("/devices/{hostname}")
    async def get_device(hostname: str, request: Request):
        reg: Registry = request.app.state.registry
        device = await reg.get_device(hostname)
        if not device:
            raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")
        return {
            "hostname": device.hostname,
            "base_url": device.base_url,
            "spec_url": device.spec_url,
            "reachable": device.reachable,
            "pod_active": device.pod_active,
            "last_check": device.last_check,
            "transport": device.transport,
            "rate_limit_rps": device.rate_limit_rps,
            "spawn_error": device.spawn_error,
        }

    @protected.get("/devices/{hostname}/tools")
    async def get_device_tools(hostname: str, request: Request):
        reg: Registry = request.app.state.registry
        device = await reg.get_device(hostname)
        if not device:
            raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")
        if not device.pod_active:
            raise HTTPException(status_code=409, detail=f"Device '{hostname}' has no active pod")

        manifest_dict = await reg.get_manifest(hostname)
        if not manifest_dict:
            raise HTTPException(status_code=409, detail=f"No manifest cached for '{hostname}'")

        tools = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "schema": t.get("schema", {}),
                "method": t.get("method", ""),
                "path": t.get("path", ""),
            }
            for t in manifest_dict.get("tools", [])
        ]
        return {"hostname": hostname, "tools": tools, "count": len(tools)}

    # --- SSE endpoints (mode-aware) ---

    @protected.get("/devices/{hostname}/sse")
    async def device_sse_stream(
        request: Request,
        hostname: str,
        session_id: str | None = Query(None),
        client_id: str | None = Query(None),  # deprecated alias
    ):
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode
        device = await reg.get_device(hostname)

        if not device or not device.pod_active:
            raise HTTPException(status_code=404, detail="Device pod not found or not active")
        if device.transport != "sse":
            raise HTTPException(status_code=400, detail="Device transport is not SSE")

        if mode == "distributed":
            # Distributed: server-assigned session ID; route results via Redis pub/sub
            session_router = request.app.state.session_router
            effective_id = str(uuid.uuid4())
            endpoint_url = f"/devices/{hostname}/messages?session_id={effective_id}"
            await session_router.register(effective_id, hostname, _GATEWAY_ID)

            async def event_generator():
                metrics.active_sse_connections.inc()
                try:
                    yield {"event": "endpoint", "data": endpoint_url}
                    try:
                        async for result in session_router.subscribe(effective_id):
                            yield {"event": "message", "data": json.dumps(result)}
                    except asyncio.CancelledError:
                        pass
                    finally:
                        await session_router.delete(effective_id)
                finally:
                    metrics.active_sse_connections.dec()

            return EventSourceResponse(event_generator())
        else:
            # Embedded: in-process SSE transport via DeviceProfile.pod
            profile = reg.get_profile(hostname)
            if not profile or not profile.pod:
                raise HTTPException(status_code=404, detail="Device pod not found")

            # Always server-assigned — ignore client-supplied session_id/client_id
            # to prevent session hijacking (S2).
            effective_id = str(uuid.uuid4())
            endpoint_url = f"/devices/{hostname}/messages?session_id={effective_id}"
            transport = profile.pod._ensure_sse_transport()
            transport.register_client(effective_id, endpoint_url)

            async def _counted_stream():
                metrics.active_sse_connections.inc()
                try:
                    async for ev in transport.event_stream(effective_id):
                        yield ev
                finally:
                    metrics.active_sse_connections.dec()

            return EventSourceResponse(_counted_stream())

    @protected.post("/devices/{hostname}/messages", dependencies=[Depends(rate_limit("600/minute", "messages"))])
    async def device_sse_message(
        hostname: str,
        request: Request,
        session_id: str | None = Query(None),
        client_id: str | None = Query(None),  # deprecated alias
    ):
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode
        device = await reg.get_device(hostname)

        if not device or not device.pod_active:
            raise HTTPException(status_code=404, detail="Device pod not found or not active")
        if device.transport != "sse":
            raise HTTPException(status_code=400, detail="Device transport is not SSE")

        effective_id = session_id or client_id
        if not effective_id:
            raise HTTPException(status_code=400, detail="session_id is required")

        payload = await request.json()
        _caller = getattr(request.state, "auth_caller", "unknown")
        _rid = getattr(request.state, "request_id", "-")

        if mode == "distributed":
            request_id = str(uuid.uuid4())
            await request.app.state.registry._backend.publish_tool_call(
                hostname=hostname,
                request_id=request_id,
                session_id=effective_id,
                gateway_id=_GATEWAY_ID,
                message=payload,
            )
            # Guard against a lost call (no worker consuming): if no result is
            # marked within the timeout, emit an error event on the SSE stream
            # so the client doesn't hang forever (F6).
            if isinstance(payload, dict) and payload.get("id") is not None:
                _timeout = cfg.get("registry", {}).get("tool_call_timeout", 30)
                _watcher = asyncio.create_task(
                    _watch_tool_call_timeout(
                        request.app.state.redis,
                        request.app.state.session_router,
                        effective_id,
                        request_id,
                        payload.get("id"),
                        _timeout,
                    )
                )
                request.app.state.bg_tasks.add(_watcher)
                _watcher.add_done_callback(request.app.state.bg_tasks.discard)
            logger.bind(
                event="audit",
                hostname=hostname,
                caller=_caller,
                method=payload.get("method", "?"),
                status="dispatched",
                rid=_rid,
            ).info("tool dispatch")
            return {"status": "accepted"}
        else:
            profile = reg.get_profile(hostname)
            if not profile or not profile.pod:
                raise HTTPException(status_code=500, detail="Pod reference lost")
            sse_transport = profile.pod.sse_transport
            if not sse_transport:
                raise HTTPException(status_code=500, detail="SSE transport not initialised")
            _t = time.perf_counter()
            response = await sse_transport.handle_message(effective_id, payload)
            _dur = (time.perf_counter() - _t) * 1000
            _status = "ok" if response and "result" in response else "error"
            _method = payload.get("method", "?") if isinstance(payload, dict) else "?"
            metrics.tool_calls_total.labels(hostname=hostname, method=_method, status=_status).inc()
            metrics.tool_call_duration_seconds.labels(hostname=hostname).observe(_dur / 1000.0)
            logger.bind(
                event="audit",
                hostname=hostname,
                caller=_caller,
                method=payload.get("method", "?"),
                status=_status,
                duration_ms=round(_dur, 1),
                rid=_rid,
            ).info("tool dispatch")
            return response

    @protected.delete("/devices/{hostname}")
    async def unregister_device(hostname: str, request: Request):
        reg: Registry = request.app.state.registry
        await reg.deregister_device(hostname)
        return {"status": "removed", "hostname": hostname}

    @protected.get("/metrics/summary")
    async def get_metrics_summary(request: Request):
        # Human-readable JSON snapshot on the API port (auth-protected; F15 will
        # scope-gate this to metrics:read). Prometheus exposition is served
        # separately on the dedicated metrics port — see metrics.start_metrics_server.
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode
        devices = await reg.list_devices()
        reachable_count = sum(1 for d in devices if d.reachable)

        metrics: dict = {
            "mode": mode,
            "active_pods": sum(1 for d in devices if d.pod_active),
            "reachable_devices": reachable_count,
            "unreachable_devices": len(devices) - reachable_count,
            "total_registered": len(devices),
        }

        if mode == "embedded":
            metrics["device_rate_limits"] = {d.hostname: {"rate_limit_rps": d.rate_limit_rps} for d in devices}

        return metrics

    _app.include_router(protected)
    return _app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    _cfg = app.state.config
    host = _cfg.get("server", {}).get("host", "0.0.0.0")  # nosec B104 — bind-all intended in containers
    port = _cfg.get("server", {}).get("port", 8000)
    logger.info(f"Starting uvicorn on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level=_cfg.get("logging", {}).get("level", "INFO").lower())
