"""
Device MCP Gateway FastAPI entrypoint.
"""

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from sse_starlette import EventSourceResponse

from device_mcp_gateway.cfg.settings import load_config
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway.logging.setup import setup_logging
from device_mcp_gateway.storage.sqlite_store import SqliteDeviceStore

app = FastAPI(title="Device MCP Gateway", version="0.1.0")

config = load_config()
setup_logging(level=config.get("logging", {}).get("level", "INFO"))

# --- Gateway-level security setup ---

_gateway_cfg = config.get("gateway", {})
_gateway_api_key: str = os.getenv("MCP_GATEWAY_API_KEY") or _gateway_cfg.get("api_key") or ""
_secret_key_raw: str = os.getenv("MCP_SECRET_KEY") or _gateway_cfg.get("secret_key") or ""

_fernet: Optional[object] = None
if _secret_key_raw:
    try:
        from cryptography.fernet import Fernet

        _fernet = Fernet(_secret_key_raw.encode() if isinstance(_secret_key_raw, str) else _secret_key_raw)
        logger.info("Credential encryption enabled")
    except Exception as exc:
        logger.error(f"Invalid secret_key — credentials will be stored as plaintext: {exc}")
else:
    logger.warning("gateway.secret_key is not set — device credentials stored as plaintext")

# --- Storage and registry ---

_storage_cfg = config.get("storage", {})
_db_path = _storage_cfg.get("db_path", "./devices.db")
_store = SqliteDeviceStore(db_path=_db_path, fernet=_fernet)

registry = Registry(config=config.get("registry", {}), store=_store)

# --- Auth dependency ---

_http_bearer = HTTPBearer(auto_error=False)


async def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_http_bearer),
) -> None:
    """Validates Bearer token when gateway.api_key is configured. No-op when unset."""
    if not _gateway_api_key:
        return
    if credentials is None or credentials.credentials != _gateway_api_key:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --- Lifespan ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Device MCP Gateway starting up")
    await _store.initialize()
    await registry.load_persisted_devices()
    health_task = asyncio.create_task(registry.start_health_loop())
    try:
        yield
    finally:
        health_task.cancel()
        with suppress(asyncio.CancelledError):
            await health_task
        await registry.shutdown()


app.router.lifespan_context = lifespan


# --- Middleware ---


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - start) * 1000
    logger.info(f"{request.method} {request.url.path} -> {response.status_code} ({elapsed:.1f}ms)")
    return response


# --- Unauthenticated routes ---


@app.get("/health")
async def health_check():
    active_pods = sum(1 for profile in registry._devices.values() if profile.pod_active)
    total_devices = len(registry._devices)
    return {
        "status": "healthy",
        "active_pods": active_pods,
        "registered_devices": total_devices,
        "version": config.get("server", {}).get("version", "0.1.0"),
    }


# --- Protected routes (require Bearer token when gateway.api_key is set) ---

protected = APIRouter(dependencies=[Depends(require_auth)])


@protected.post("/devices")
async def register_device(request: Request):
    data = await request.json()
    hostname = data.get("hostname")
    base_url = data.get("base_url")

    if not hostname or not base_url:
        raise HTTPException(status_code=400, detail="hostname and base_url required")

    auth_type = (
        data.get("auth_type") or data.get("auth", {}).get("type") or config.get("auth", {}).get("type", "api_key")
    )
    auth: AbstractAuth | None = None

    if auth_type == "api_key":
        api_key = data.get("auth", {}).get("api_key") or data.get("api_key")
        header_name = data.get("auth", {}).get("header_name") or config.get("auth", {}).get("api_key", {}).get(
            "header_name", "X-API-Key"
        )
        if api_key:
            auth = ApiKeyAuth(api_key=api_key, header_name=header_name)
    elif auth_type == "oauth2":
        auth_config = data.get("auth", {})
        token_endpoint = auth_config.get("token_endpoint") or config.get("auth", {}).get("oauth2", {}).get(
            "token_endpoint"
        )
        client_id = auth_config.get("client_id") or config.get("auth", {}).get("oauth2", {}).get("client_id")
        client_secret = auth_config.get("client_secret") or config.get("auth", {}).get("oauth2", {}).get(
            "client_secret"
        )
        scopes = auth_config.get("scopes") or config.get("auth", {}).get("oauth2", {}).get("scopes", ["read"])
        if not token_endpoint or not client_id or not client_secret:
            raise HTTPException(status_code=400, detail="oauth2 requires token_endpoint, client_id, and client_secret")
        auth = OAuth2Auth(
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
        )
    elif auth_type == "none":
        auth = None
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported auth_type: {auth_type}")

    transport = data.get("transport") or config.get("transport", {}).get("default", "sse")
    spec_url = data.get("spec_url")

    profile = await registry.register_device(
        hostname=hostname,
        base_url=base_url,
        spec_url=spec_url,
        auth=auth,
        transport=transport,
    )

    return {
        "status": "registered",
        "hostname": hostname,
        "pod_active": profile.pod_active,
        "reachable": profile.reachable,
        "spawn_error": profile.spawn_error,
    }


@protected.get("/devices")
async def list_devices():
    devices = []
    for profile in registry._devices.values():
        devices.append(
            {
                "hostname": profile.hostname,
                "base_url": profile.base_url,
                "reachable": profile.reachable,
                "pod_active": profile.pod_active,
                "last_check": profile.last_reachable_check,
                "transport": profile.transport,
            }
        )
    return {"devices": devices}


@protected.get("/devices/{hostname}/sse")
async def device_sse_stream(hostname: str, client_id: str | None = Query(None)):
    profile = registry.get_device(hostname)
    if not profile or not profile.pod or not profile.pod_active:
        raise HTTPException(status_code=404, detail="Device pod not found")
    if profile.transport != "sse":
        raise HTTPException(status_code=400, detail="Device transport is not SSE")

    if not client_id:
        client_id = str(uuid.uuid4())

    transport = profile.pod._ensure_sse_transport()
    transport.register_client(client_id)
    return EventSourceResponse(transport.event_stream(client_id))


@protected.post("/devices/{hostname}/messages")
async def device_sse_message(hostname: str, request: Request, client_id: str = Query(...)):
    profile = registry.get_device(hostname)
    if not profile or not profile.pod or not profile.pod_active:
        raise HTTPException(status_code=404, detail="Device pod not found")
    if profile.transport != "sse":
        raise HTTPException(status_code=400, detail="Device transport is not SSE")

    transport = profile.pod.sse_transport
    if not transport:
        raise HTTPException(status_code=500, detail="SSE transport not initialized")

    payload = await request.json()
    response = await transport.handle_message(client_id, payload)
    return response


@protected.delete("/devices/{hostname}")
async def unregister_device(hostname: str):
    await registry.deregister_device(hostname)
    return {"status": "removed", "hostname": hostname}


@protected.get("/metrics")
async def get_metrics():
    reachable_count = sum(1 for profile in registry._devices.values() if profile.reachable)
    unreachable_count = len(registry._devices) - reachable_count
    return {
        "active_pods": sum(1 for profile in registry._devices.values() if profile.pod_active),
        "reachable_devices": reachable_count,
        "unreachable_devices": unreachable_count,
        "total_registered": len(registry._devices),
        "spec_cache_size": len(registry._spec_cache._store),
    }


app.include_router(protected)


if __name__ == "__main__":
    import uvicorn

    host = config.get("server", {}).get("host", "0.0.0.0")
    port = config.get("server", {}).get("port", 8000)
    logger.info(f"Starting uvicorn on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level=config.get("logging", {}).get("level", "INFO").lower())
