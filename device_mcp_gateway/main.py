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
"""

import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from loguru import logger
from sse_starlette import EventSourceResponse

from device_mcp_gateway import __version__
from device_mcp_gateway.cfg import load_config, resolve_mode, warn_unsafe_settings
from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_log, audit_request
from device_mcp_gateway.core.backoff import jittered
from device_mcp_gateway.core.errors import RPC_NO_WORKER, rpc_error
from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway import metrics
from device_mcp_gateway.observability import tracing
from device_mcp_gateway.logging_setup import setup_logging
from device_mcp_gateway.ratelimit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    client_ip_key_func,
    rate_limit,
)
from device_mcp_gateway.rbac import (
    SCOPE_DEVICES_READ,
    SCOPE_DEVICES_WRITE,
    SCOPE_METRICS_READ,
    SCOPE_TOOLS_CALL,
    authenticate_request,
    build_authenticator,
    require_scope,
)
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.schemas import (
    BreakerState,
    DeviceDiagnostics,
    DeviceListResponse,
    OverviewResponse,
)
from device_mcp_gateway.security.url_policy import UrlPolicyError, validate_target_url
from device_mcp_gateway.shared.crypto import CredentialCodec
from device_mcp_gateway.shared.registry_backend import (
    MemoryRegistryBackend,
    RedisRegistryBackend,
)

# Gateway instance ID — used to tag SSE sessions in distributed mode.
_GATEWAY_ID = os.getenv("GATEWAY_ID", str(uuid.uuid4()))


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


async def _watch_tool_call_timeout(
    redis, session_router, session_id, request_id, msg_id, timeout, hostname="?", rid=None
):
    """Emit a JSON-RPC timeout error on the SSE stream if no worker responds.

    Cross-replica safe: the worker sets result:{request_id} in Redis when it
    handles the call, so this watcher (which may run on a different gateway
    replica than the one holding the SSE stream) checks that shared marker
    rather than observing the pub/sub channel directly (F6). The emitted error
    carries the catalogued `no_worker` reason + the rid so the caller can
    diagnose and correlate with the access log (F-51).
    """
    try:
        await asyncio.sleep(timeout)
        if await redis.get(f"result:{request_id}"):
            return  # worker handled it
        metrics.tool_call_timeouts_total.labels(hostname=hostname).inc()
        await session_router.publish_result(
            session_id,
            rpc_error(
                RPC_NO_WORKER,
                msg_id,
                rid=rid,
                request_id=request_id,
                message=f"Tool call timed out after {timeout}s — no worker responded",
            ),
        )
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.warning(f"tool-call timeout watcher failed for request {request_id}")


async def _count_live_workers(redis) -> int:
    """Count workers with a live heartbeat (distributed mode).

    `workers:active` can retain ids of crashed workers that never deregistered, so
    membership alone overstates the fleet — gate on the heartbeat key, which the
    worker refreshes and which expires on death. Used as a degraded signal in
    /health (SRE #7): a gateway with zero live workers still serves read endpoints,
    but tool calls will time out, and operators/UI should see that.
    """
    ids = await redis.smembers("workers:active")
    if not ids:
        return 0
    pipe = redis.pipeline()
    for wid in ids:
        pipe.exists(f"worker:{wid}:heartbeat")
    return sum(1 for present in await pipe.execute() if present)


_GAUGE_LEADER_LOCK = "gateway:gauge-leader"


async def _acquire_gauge_leadership(redis, leader_id: str, ttl: int) -> bool:
    """Claim/refresh the gauge-refresh leader lock (SRE O4).

    SET NX to take it; if we already hold it, refresh the TTL so leadership is
    sticky while this replica is alive but lapses soon after it dies, letting
    another replica take over. Mirrors the worker reconciler's election.
    """
    if await redis.set(_GAUGE_LEADER_LOCK, leader_id, nx=True, ex=ttl):
        return True
    if (await redis.get(_GAUGE_LEADER_LOCK)) == leader_id:
        await redis.expire(_GAUGE_LEADER_LOCK, ttl)
        return True
    return False


async def _refresh_device_gauges(app: FastAPI, interval: float) -> None:
    """Periodically refresh device-fleet gauges from the registry.

    Prometheus collection is synchronous, but ``list_devices()`` is async, so we
    cannot compute these inside a collector — we poll on a timer instead.

    Leader-gated (SRE O4): in distributed mode every gateway replica runs this
    loop, so without gating each would do a full ``list_devices()`` every cycle
    (×replicas Redis load). Only the lock holder computes the fleet gauges; the
    others idle and stand ready to take over if the leader dies. Consequence: the
    fleet gauges are populated on one replica at a time, so aggregate them with
    ``max()`` across replicas in Prometheus. Embedded mode (no Redis) is a single
    process, so it always refreshes.
    """
    redis = getattr(app.state, "redis", None)
    leader_id = uuid.uuid4().hex
    lock_ttl = max(int(interval * 2), 30)
    while True:
        try:
            reg = app.state.registry
            is_leader = redis is None or await _acquire_gauge_leadership(redis, leader_id, lock_ttl)
            if reg is not None and is_leader:
                devices = await reg.list_devices()
                metrics.registered_devices.set(len(devices))
                metrics.active_pods.set(sum(1 for d in devices if d.pod_active))
                metrics.reachable_devices.set(sum(1 for d in devices if d.reachable))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("device gauge refresh failed")
        await asyncio.sleep(jittered(interval))  # F-61: de-sync leader-election/refresh across replicas


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

    # SSRF policy for device target URLs (Tier-0 F-02). base_url/spec_url are fetched
    # server-side, so reject internal/loopback/link-local targets unless explicitly allowed
    # (security.allow_private_targets, or the MCP_ALLOW_PRIVATE_TARGETS env override).
    _allow_private_targets = bool(cfg.get("security", {}).get("allow_private_targets", False)) or os.getenv(
        "MCP_ALLOW_PRIVATE_TARGETS", ""
    ).lower() in ("1", "true", "yes")

    def _check_target_url(url: str | None, field: str) -> None:
        if not url:
            return
        try:
            validate_target_url(url, allow_private=_allow_private_targets)
        except UrlPolicyError as exc:
            raise HTTPException(status_code=400, detail=f"Rejected {field}: {exc}")

    def _parse_auth(data: dict) -> AbstractAuth | None:
        auth_type = (
            data.get("auth_type") or data.get("auth", {}).get("type") or cfg.get("auth", {}).get("type", "api_key")
        )
        if auth_type == "api_key":
            auth_cfg = data.get("auth", {})
            api_key = auth_cfg.get("api_key") or data.get("api_key")
            header_name = auth_cfg.get("header_name") or cfg.get("auth", {}).get("api_key", {}).get(
                "header_name", "X-API-Key"
            )
            if not api_key:
                return None
            # F-43: optional non-header placement + scheme prefix.
            try:
                return ApiKeyAuth(
                    api_key=api_key,
                    header_name=header_name,
                    location=auth_cfg.get("location", "header"),
                    name=auth_cfg.get("name"),
                    value_prefix=auth_cfg.get("value_prefix", ""),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid api_key auth: {exc}")
        if auth_type == "oauth2":
            auth_cfg = data.get("auth", {})
            oauth_defaults = cfg.get("auth", {}).get("oauth2", {})
            token_endpoint = auth_cfg.get("token_endpoint") or oauth_defaults.get("token_endpoint")
            client_id = auth_cfg.get("client_id") or oauth_defaults.get("client_id")
            client_secret = auth_cfg.get("client_secret") or oauth_defaults.get("client_secret")
            scopes = auth_cfg.get("scopes") or oauth_defaults.get("scopes", ["read"])
            if not token_endpoint or not client_id or not client_secret:
                raise HTTPException(
                    status_code=400, detail="oauth2 requires token_endpoint, client_id, and client_secret"
                )
            # F-42: optional grant/style/audience and provider-specific knobs.
            try:
                return OAuth2Auth(
                    token_endpoint=token_endpoint,
                    client_id=client_id,
                    client_secret=client_secret,
                    scopes=scopes,
                    grant_type=auth_cfg.get("grant_type", "client_credentials"),
                    auth_style=auth_cfg.get("auth_style", "request_body"),
                    audience=auth_cfg.get("audience"),
                    username=auth_cfg.get("username"),
                    password=auth_cfg.get("password"),
                    refresh_token=auth_cfg.get("refresh_token"),
                    extra_params=auth_cfg.get("extra_params"),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid oauth2 auth: {exc}")
        if auth_type == "none":
            return None
        raise HTTPException(status_code=400, detail=f"Unsupported auth_type: {auth_type}")

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
    # Strong refs to fire-and-forget timeout watchers so they aren't GC'd.
    _app.state.bg_tasks = set()
    # Embedded-mode session→owner map for principal↔session binding (F-37). In
    # distributed mode the owner lives on the Redis session hash instead, so the
    # binding survives across gateway replicas.
    _app.state.session_owners = {}
    # Short-TTL cache for the UI read aggregate (SRE O4) so a polling dashboard
    # doesn't trigger a fresh list_devices() on every request. Per-replica; ETag is
    # a content hash so it's stable across replicas.
    _read_cache_ttl: float = cfg.get("gateway", {}).get("read_cache_ttl", 5)
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

    # --- Unauthenticated routes ---

    @_app.get("/health", dependencies=[Depends(rate_limit("300/minute", "health"))])
    async def health_check(request: Request):
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode

        devices = await reg.list_devices()
        active = sum(1 for d in devices if d.pod_active)

        payload = {
            "status": "healthy",
            "mode": mode,
            "active_pods": active,
            "registered_devices": len(devices),
            "version": cfg.get("server", {}).get("version", __version__),
        }

        # Distributed mode: expose worker-fleet liveness as a degraded signal (SRE
        # #7). Stays HTTP 200 (this is the liveness target — a worker outage must
        # not restart the gateway), but flips status to "degraded" with a count so
        # the UI/operators can see that tool calls have no workers to serve them.
        if mode == "distributed":
            redis = request.app.state.redis
            live_workers = await _count_live_workers(redis) if redis is not None else 0
            payload["live_workers"] = live_workers
            if live_workers == 0:
                payload["status"] = "degraded"

        return payload

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

    # Router-level: authenticate every protected request to a Principal. Each route
    # then authorizes on a specific scope via require_scope(...).
    protected = APIRouter(dependencies=[Depends(authenticate_request)])

    @protected.post(
        "/devices",
        dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE)), Depends(rate_limit("60/minute", "devices_post"))],
    )
    async def register_device(request: Request):
        data = await request.json()
        reg: Registry = request.app.state.registry
        hostname = data.get("hostname")
        base_url = data.get("base_url")

        if not hostname or not base_url:
            raise HTTPException(status_code=400, detail="hostname and base_url required")
        _validate_hostname(hostname)
        _check_target_url(base_url, "base_url")

        existing = await reg.get_device(hostname)
        if existing:
            raise HTTPException(status_code=409, detail=f"Device '{hostname}' already registered; use PUT to update")

        auth = _parse_auth(data)
        transport = data.get("transport") or cfg.get("transport", {}).get("default", "sse")
        _validate_transport(transport)
        spec_url = data.get("spec_url")
        _check_target_url(spec_url, "spec_url")
        rate_limit_rps = _parse_rate_limit(data)

        device_cfg = await reg.register_device(
            hostname=hostname,
            base_url=base_url,
            spec_url=spec_url,
            auth=auth,
            transport=transport,
            rate_limit_rps=rate_limit_rps,
        )

        audit_request(request, "device.create", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname)
        return {
            "status": "registered",
            "hostname": hostname,
            "pod_active": device_cfg.pod_active,
            "reachable": device_cfg.reachable,
            "spawn_error": device_cfg.spawn_error,
            # Async registration (F-11): True when the device was accepted but its
            # pod is still being provisioned in the background — poll GET /devices/{h}.
            "provisioning": reg.is_provisioning(hostname),
        }

    @protected.put("/devices/{hostname}", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
    async def update_device(hostname: str, request: Request):
        reg: Registry = request.app.state.registry
        existing = await reg.get_device(hostname)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")

        data = await request.json()
        base_url = data.get("base_url") or existing.base_url
        spec_url = data.get("spec_url", existing.spec_url)
        # Re-validate target URLs on update (a PUT can change base_url/spec_url) — Tier-0 F-02.
        _check_target_url(base_url, "base_url")
        _check_target_url(spec_url, "spec_url")

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

        audit_request(request, "device.update", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname)
        return {
            "status": "updated",
            "hostname": hostname,
            "pod_active": device_cfg.pod_active,
            "reachable": device_cfg.reachable,
            "spawn_error": device_cfg.spawn_error,
            "provisioning": reg.is_provisioning(hostname),  # F-11 (see register_device)
        }

    @protected.get(
        "/devices",
        response_model=DeviceListResponse,
        dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
    )
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

    @protected.get("/devices/{hostname}", dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))])
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

    @protected.get("/devices/{hostname}/tools", dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))])
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

    @protected.get(
        "/devices/{hostname}/diagnostics",
        dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
        response_model=DeviceDiagnostics,
    )
    async def device_diagnostics(hostname: str, request: Request):
        """Self-service "why is my device down?" diagnostics (F-52): registry
        status, last check + age, spec/manifest state, spawn error, and the
        circuit breaker (in-process pods only)."""
        reg: Registry = request.app.state.registry
        mode = request.app.state.mode
        device = await reg.get_device(hostname)
        if not device:
            raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")

        manifest_dict = await reg.get_manifest(hostname)
        tool_count = len(manifest_dict.get("tools", [])) if manifest_dict else 0
        age = (time.time() - device.last_check) if device.last_check else None

        # Breaker state is per-pod. In embedded mode the pod is in-process and we can
        # read it; in distributed mode it lives in the worker, unreachable from here.
        if mode == "distributed":
            breaker = BreakerState(available=False, note="pod runs on a worker; breaker not readable from the gateway")
        else:
            profile = reg.get_profile(hostname)
            if profile and profile.pod_active and profile.pod:
                breaker = BreakerState(available=True, **profile.pod.breaker_snapshot())
            else:
                breaker = BreakerState(available=False, note="no active pod")

        return DeviceDiagnostics(
            hostname=device.hostname,
            mode=mode,
            base_url=device.base_url,
            spec_url=device.spec_url,
            transport=device.transport,
            reachable=device.reachable,
            pod_active=device.pod_active,
            worker_id=device.worker_id,
            last_check=device.last_check or None,
            last_check_age_seconds=round(age, 1) if age is not None else None,
            spec_hash=device.spec_hash,
            has_manifest=manifest_dict is not None,
            tool_count=tool_count,
            spawn_error=device.spawn_error,
            breaker=breaker,
        )

    # --- Dead-letter queue operations (F-10, distributed mode) ---

    def _require_distributed(request: Request):
        """Return the Redis backend, or 400 in embedded mode (no DLQ in-process)."""
        if request.app.state.mode != "distributed":
            raise HTTPException(status_code=400, detail="Dead-letter queue is only available in distributed mode")
        return request.app.state.registry._backend

    async def _optional_ids(request: Request) -> list[str] | None:
        """Parse an optional ``{"ids": [...]}`` JSON body; None when absent/empty."""
        try:
            data = await request.json()
        except Exception:
            return None
        if isinstance(data, dict):
            ids = data.get("ids")
            if isinstance(ids, list) and all(isinstance(i, str) for i in ids):
                return ids or None
        return None

    @protected.get("/devices/{hostname}/deadletter", dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))])
    async def list_dead_letters(hostname: str, request: Request, limit: int = Query(50, ge=1, le=500)):
        """Inspect a device's dead-lettered tool calls (newest first) — F-10."""
        backend = _require_distributed(request)
        entries = await backend.dead_letter_list(hostname, count=limit)
        return {"hostname": hostname, "count": len(entries), "entries": entries}

    @protected.post("/devices/{hostname}/deadletter/replay", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
    async def replay_dead_letters(hostname: str, request: Request, limit: int = Query(50, ge=1, le=500)):
        """Re-publish dead-lettered calls onto the device's call stream and remove
        them from the DLQ. Optional JSON body ``{"ids": [...]}`` replays specific
        entries; otherwise up to ``limit`` oldest are replayed (F-10)."""
        backend = _require_distributed(request)
        ids = await _optional_ids(request)
        replayed = await backend.dead_letter_replay(hostname, ids=ids, count=limit)
        audit_request(
            request, "device.deadletter.replay", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname, count=replayed
        )
        return {"hostname": hostname, "replayed": replayed}

    @protected.delete("/devices/{hostname}/deadletter", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
    async def purge_dead_letters(hostname: str, request: Request):
        """Drain a device's DLQ. Optional JSON body ``{"ids": [...]}`` deletes
        specific entries; otherwise the whole queue is dropped (F-10)."""
        backend = _require_distributed(request)
        ids = await _optional_ids(request)
        removed = await backend.dead_letter_purge(hostname, ids=ids)
        audit_request(
            request, "device.deadletter.purge", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname, removed=removed
        )
        return {"hostname": hostname, "removed": removed}

    # --- SSE endpoints (mode-aware) ---

    @protected.get("/devices/{hostname}/sse", dependencies=[Depends(require_scope(SCOPE_TOOLS_CALL))])
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

        # Bind the session to the principal that opens it (F-37) so another caller
        # holding tools:call can't post to it. ``principal`` is set by the auth
        # dependency on this protected route.
        _principal = getattr(request.state, "principal", None)
        _owner_subject = _principal.subject if _principal else "unknown"

        if mode == "distributed":
            # Distributed: server-assigned session ID; route results via Redis pub/sub
            session_router = request.app.state.session_router
            effective_id = str(uuid.uuid4())
            endpoint_url = f"/devices/{hostname}/messages?session_id={effective_id}"
            await session_router.register(effective_id, hostname, _GATEWAY_ID, owner=_owner_subject)

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
            request.app.state.session_owners[effective_id] = _owner_subject  # F-37

            async def _counted_stream():
                metrics.active_sse_connections.inc()
                try:
                    async for ev in transport.event_stream(effective_id):
                        yield ev
                finally:
                    metrics.active_sse_connections.dec()
                    request.app.state.session_owners.pop(effective_id, None)

            return EventSourceResponse(_counted_stream())

    @protected.post(
        "/devices/{hostname}/messages",
        dependencies=[Depends(require_scope(SCOPE_TOOLS_CALL)), Depends(rate_limit("600/minute", "messages"))],
    )
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
        _principal = getattr(request.state, "principal", None)
        _subject = _principal.subject if _principal else "unknown"
        _rid = getattr(request.state, "request_id", "-")

        # Principal↔session binding (F-37): a session may only be posted to by the
        # principal that opened it. Distributed mode stores the owner on the Redis
        # session hash (survives across replicas); embedded mode keeps it in-process.
        if mode == "distributed":
            _sess = await request.app.state.session_router.get(effective_id)
            _owner = _sess.get("owner") if _sess else None
        else:
            _owner = request.app.state.session_owners.get(effective_id)
        if _owner is not None and _owner != _subject:
            raise HTTPException(status_code=403, detail="session_id is bound to a different principal")

        if mode == "distributed":
            _backend = request.app.state.registry._backend
            # Admission control (F-06): if the device's call stream is backed up
            # past the watermark, the worker isn't draining it and a new call
            # would queue behind work that gets silently trimmed at MAXLEN —
            # surfacing only as a 30s client timeout. Fast-fail with 429 instead
            # so the backpressure is visible and retryable at the source.
            _backlog_limit = cfg.get("registry", {}).get("call_backlog_limit", 1000)
            if _backlog_limit > 0 and await _backend.call_backlog(hostname) >= _backlog_limit:
                metrics.calls_rejected_overload_total.labels(hostname=hostname).inc()
                audit_log(
                    "tool dispatch shed: call backlog over watermark",
                    level="WARNING",
                    hostname=hostname,
                    subject=_subject,
                    status="rejected_overload",
                    rid=_rid,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Device '{hostname}' is overloaded; retry shortly",
                    headers={"Retry-After": "1"},
                )
            request_id = str(uuid.uuid4())
            _method = payload.get("method", "?") if isinstance(payload, dict) else "?"
            # Open a dispatch span and inject its W3C context so the worker's
            # execution span joins the same trace (F-14). No-op when tracing is off.
            with tracing.start_span(
                "mcp.tool_dispatch",
                attributes={"mcp.hostname": hostname, "mcp.method": _method, "mcp.rid": _rid},
            ):
                _carrier = tracing.inject_carrier()
                await _backend.publish_tool_call(
                    hostname=hostname,
                    request_id=request_id,
                    session_id=effective_id,
                    gateway_id=_GATEWAY_ID,
                    message=payload,
                    rid=_rid,
                    traceparent=_carrier.get("traceparent", ""),
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
                        hostname,
                        _rid,
                    )
                )
                request.app.state.bg_tasks.add(_watcher)
                _watcher.add_done_callback(request.app.state.bg_tasks.discard)
            audit_log(
                "tool dispatch",
                hostname=hostname,
                subject=_subject,
                method=payload.get("method", "?"),
                status="dispatched",
                rid=_rid,
            )
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
            audit_log(
                "tool dispatch",
                hostname=hostname,
                subject=_subject,
                method=payload.get("method", "?"),
                status=_status,
                duration_ms=round(_dur, 1),
                rid=_rid,
            )
            return response

    @protected.delete("/devices/{hostname}", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
    async def unregister_device(hostname: str, request: Request):
        reg: Registry = request.app.state.registry
        await reg.deregister_device(hostname)
        audit_request(request, "device.delete", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname)
        return {"status": "removed", "hostname": hostname}

    @protected.get("/metrics/summary", dependencies=[Depends(require_scope(SCOPE_METRICS_READ))])
    async def get_metrics_summary(request: Request):
        # Human-readable JSON snapshot on the API port (scope-gated to metrics:read).
        # Prometheus exposition is served separately on the dedicated metrics port —
        # see metrics.start_metrics_server.
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

    @protected.get(
        "/admin/overview",
        response_model=OverviewResponse,
        dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
    )
    async def admin_overview(request: Request):
        # Single-call aggregate for the UI/BFF (F14): fleet counts + the device list
        # in one round-trip, so the dashboard's landing screen isn't N+1 requests.
        # Served from a short-TTL per-replica cache with an ETag (SRE O4) so a
        # polling dashboard doesn't hit Redis (list_devices) on every request and
        # can short-circuit with a 304 when nothing changed.
        cache = request.app.state.overview_cache
        now = time.monotonic()
        if cache["body"] is None or (now - cache["ts"]) >= _read_cache_ttl:
            reg: Registry = request.app.state.registry
            mode = request.app.state.mode
            devices = await reg.list_devices()
            reachable_count = sum(1 for d in devices if d.reachable)
            body = {
                "mode": mode,
                "counts": {
                    "total": len(devices),
                    "active_pods": sum(1 for d in devices if d.pod_active),
                    "reachable": reachable_count,
                    "unreachable": len(devices) - reachable_count,
                },
                "devices": [
                    {
                        "hostname": d.hostname,
                        "base_url": d.base_url,
                        "transport": d.transport,
                        "reachable": d.reachable,
                        "pod_active": d.pod_active,
                        "last_check": d.last_check,
                        "rate_limit_rps": d.rate_limit_rps,
                    }
                    for d in devices
                ],
            }
            etag = '"' + hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16] + '"'
            cache.update(ts=now, etag=etag, body=body)

        etag = cache["etag"]
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(
            content=cache["body"],
            headers={"ETag": etag, "Cache-Control": f"max-age={int(_read_cache_ttl)}"},
        )

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
