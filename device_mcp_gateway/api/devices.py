# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Device CRUD + tools/diagnostics routes.

The register/update input helpers (`_parse_auth`, `_check_target_url`, validators)
were hoisted out of the ``create_app`` closure in the router split: they now take
``cfg``/``allow_private`` explicitly, with the handlers reading both from
``request.app.state.config`` per request.
"""

from __future__ import annotations

import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.rbac import SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, require_scope
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.schemas import (
    BreakerState,
    DeviceDetail,
    DeviceDiagnostics,
    DeviceListResponse,
    DeviceMutationResult,
    DeviceSummary,
    ToolChangeRecord,
    ToolsDiffResponse,
)
from device_mcp_gateway.security.url_policy import UrlPolicyError, resolve_allow_private, validate_target_url

router = APIRouter()

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$")


def _validate_hostname(hostname: str) -> None:
    if not hostname or len(hostname) > 253 or not _HOSTNAME_RE.match(hostname):
        raise HTTPException(
            status_code=400,
            detail="hostname must be 1–253 characters, start and end with a letter or digit, "
            "and contain only letters, digits, hyphens, or dots",
        )


def _validate_transport(transport: str) -> None:
    if transport != "sse":
        raise HTTPException(
            status_code=400,
            detail=f"Transport '{transport}' is not supported in gateway mode; use 'sse'",
        )


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


def _check_target_url(url: str | None, field: str, allow_private: bool) -> None:
    """SSRF policy for device target URLs (Tier-0 F-02). base_url/spec_url are fetched
    server-side, so reject internal/loopback/link-local targets unless explicitly allowed
    (security.allow_private_targets, or the MCP_ALLOW_PRIVATE_TARGETS env override)."""
    if not url:
        return
    try:
        validate_target_url(url, allow_private=allow_private)
    except UrlPolicyError as exc:
        raise HTTPException(status_code=400, detail=f"Rejected {field}: {exc}")


def _parse_auth(data: dict, cfg: dict, allow_private: bool) -> AbstractAuth | None:
    auth_type = data.get("auth_type") or data.get("auth", {}).get("type") or cfg.get("auth", {}).get("type", "api_key")
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
            raise HTTPException(status_code=400, detail="oauth2 requires token_endpoint, client_id, and client_secret")
        # SSRF-2: the gateway POSTs the client_secret to token_endpoint, so it is an
        # outbound device target too — run it through the same URL policy as base_url/
        # spec_url. Without this a devices:write caller could exfiltrate the secret to
        # an internal/metadata address (F-02/F-29).
        _check_target_url(token_endpoint, "token_endpoint", allow_private)
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


@router.post(
    "/devices",
    response_model=DeviceMutationResult,
    dependencies=[
        Depends(require_scope(SCOPE_DEVICES_WRITE)),
        # Per-IP burst guard + per-principal fair-share (F-16). The per-principal
        # budget is set above a single IP's so a legitimate client spread over a
        # few IPs isn't throttled, while one identity can't multiply its budget
        # across unlimited source IPs.
        Depends(rate_limit("60/minute", "devices_post")),
        Depends(rate_limit_principal("120/minute", "devices_post")),
    ],
)
async def register_device(request: Request):
    data = await request.json()
    reg: Registry = request.app.state.registry
    cfg = request.app.state.config
    allow_private = resolve_allow_private(cfg)
    hostname = data.get("hostname")
    base_url = data.get("base_url")

    if not hostname or not base_url:
        raise HTTPException(status_code=400, detail="hostname and base_url required")
    _validate_hostname(hostname)
    _check_target_url(base_url, "base_url", allow_private)

    existing = await reg.get_device(hostname)
    if existing:
        raise HTTPException(status_code=409, detail=f"Device '{hostname}' already registered; use PUT to update")

    auth = _parse_auth(data, cfg, allow_private)
    transport = data.get("transport") or cfg.get("transport", {}).get("default", "sse")
    _validate_transport(transport)
    spec_url = data.get("spec_url")
    _check_target_url(spec_url, "spec_url", allow_private)
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
    # Async registration (F-11): provisioning=True when the device was accepted
    # but its pod is still spawning in the background — poll GET /devices/{h}.
    return DeviceMutationResult(
        status="registered",
        provisioning=reg.is_provisioning(hostname),
        device=DeviceDetail.from_config(device_cfg),
    )


@router.put(
    "/devices/{hostname}",
    response_model=DeviceMutationResult,
    dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))],
)
async def update_device(hostname: str, request: Request):
    reg: Registry = request.app.state.registry
    cfg = request.app.state.config
    allow_private = resolve_allow_private(cfg)
    existing = await reg.get_device(hostname)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")

    data = await request.json()
    base_url = data.get("base_url") or existing.base_url
    spec_url = data.get("spec_url", existing.spec_url)
    # Re-validate target URLs on update (a PUT can change base_url/spec_url) — Tier-0 F-02.
    _check_target_url(base_url, "base_url", allow_private)
    _check_target_url(spec_url, "spec_url", allow_private)

    _AUTH_KEYS = {"auth_type", "auth", "api_key"}
    auth: AbstractAuth | None = None
    keep_auth = False
    if _AUTH_KEYS & data.keys():
        auth = _parse_auth(data, cfg, allow_private)
    else:
        # No auth field in the PUT body → preserve the stored credentials. We must
        # NOT reconstruct them here: in distributed mode existing.auth_config is
        # Fernet ciphertext, and parsing it as JSON failed and silently wiped the
        # device's credentials. Let the registry carry the stored record verbatim.
        keep_auth = True
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
        keep_auth=keep_auth,
    )

    audit_request(request, "device.update", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname)
    return DeviceMutationResult(
        status="updated",
        provisioning=reg.is_provisioning(hostname),  # F-11 (see register_device)
        device=DeviceDetail.from_config(device_cfg),
    )


@router.get(
    "/devices",
    response_model=DeviceListResponse,
    dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
)
async def list_devices(request: Request):
    reg: Registry = request.app.state.registry
    devices = await reg.list_devices()
    return DeviceListResponse(devices=[DeviceSummary.from_config(d) for d in devices])


@router.get(
    "/devices/{hostname}",
    response_model=DeviceDetail,
    dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
)
async def get_device(hostname: str, request: Request):
    reg: Registry = request.app.state.registry
    device = await reg.get_device(hostname)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")
    return DeviceDetail.from_config(device)


@router.delete("/devices/{hostname}", dependencies=[Depends(require_scope(SCOPE_DEVICES_WRITE))])
async def unregister_device(hostname: str, request: Request):
    reg: Registry = request.app.state.registry
    await reg.deregister_device(hostname)
    audit_request(request, "device.delete", outcome=AUDIT_OUTCOME_SUCCESS, target=hostname)
    return {"status": "removed", "hostname": hostname}


@router.get("/devices/{hostname}/tools", dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))])
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


@router.get(
    "/devices/{hostname}/tools/diff",
    dependencies=[Depends(require_scope(SCOPE_DEVICES_READ))],
    response_model=ToolsDiffResponse,
)
async def get_device_tools_diff(hostname: str, request: Request):
    """Tool-set change governance (F-41): what was added/removed/changed when
    the device's tools last moved, and whether it was breaking. ``last_change``
    is ``null`` when no change has been observed since registration. Unlike
    ``/tools`` this does not require an active pod — a UI can show "the tools
    changed (and how)" even for a device that is currently down."""
    reg: Registry = request.app.state.registry
    device = await reg.get_device(hostname)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")
    record = await reg.get_last_tool_change(hostname)
    return ToolsDiffResponse(
        hostname=hostname,
        tools_revision=device.tools_revision,
        last_change=ToolChangeRecord(**record) if record else None,
    )


@router.get(
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
        tools_revision=device.tools_revision,
        spawn_error=device.spawn_error,
        breaker=breaker,
    )
