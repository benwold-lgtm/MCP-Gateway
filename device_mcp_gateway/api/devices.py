# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Device CRUD + tools/diagnostics routes.

The register/update input helpers were hoisted out of the ``create_app`` closure in the
router split: they take ``cfg``/``allow_private`` explicitly, with the handlers reading
both from ``request.app.state.config`` per request.

The **validators** then moved again, to ``registry/validation.py`` (F-67). They had made
the egress policy a property of this route rather than of registration itself, which held
only while this route was registration's sole caller — restore is the second one. They are
re-exported below under their original names, so this module reads as it did.

``_parse_auth`` stays here: it turns a *request body* into an ``AbstractAuth``, which is an
HTTP concern. Restore rebuilds its auth from an archived credential blob instead, via
``_auth_from_config`` — the inverse of what persisted it.
"""

from __future__ import annotations

import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_request
from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.credentials import ReferenceInvalid
from device_mcp_gateway.credentials.resolver import require_references
from device_mcp_gateway.auth.base import AbstractAuth
from device_mcp_gateway.auth.oauth2 import OAuth2Auth
from device_mcp_gateway.ratelimit import rate_limit, rate_limit_principal
from device_mcp_gateway.security import fingerprint as fp
from device_mcp_gateway.rbac import SCOPE_DEVICES_READ, SCOPE_DEVICES_WRITE, require_scope
from device_mcp_gateway.registry.server import Registry
from device_mcp_gateway.schemas import (
    BreakerState,
    DeviceDetail,
    DeviceDiagnostics,
    TlsProfileInfo,
    DeviceListResponse,
    DeviceMutationResult,
    DeviceSummary,
    ToolChangeRecord,
    ToolsDiffResponse,
)
from device_mcp_gateway.security.url_policy import (
    resolve_allow_private,
    resolve_allowed_ports,
)

# The registration gates live in the registry package, not here, so restore runs exactly
# the ones this route does (F-67). Re-exported under their original private names because
# they read as local helpers at every call site below — and because moving them must not
# be an API change for anything that imports them.
from device_mcp_gateway.registry.validation import (  # noqa: F401  (re-exported)
    _check_target_url,
    _parse_rate_limit,
    _read_upstream,
    _validate_hostname,
    _validate_transport,
    _validate_upstream,
    check_credential_form,
    validate_device_registration,
)

# A SHA-256 digest, hex. Validated rather than stored raw so a typo becomes a 400 at
# registration instead of a device that quarantines itself on its very first probe.
_SPKI_RE = re.compile(r"[0-9a-f]{64}")

router = APIRouter()


def _parse_auth(
    data: dict, cfg: dict, allow_private: bool, allowed_ports: set[int] | None = None
) -> AbstractAuth | None:
    auth_type = data.get("auth_type") or data.get("auth", {}).get("type") or cfg.get("auth", {}).get("type", "api_key")
    if auth_type == "api_key":
        auth_cfg = data.get("auth", {})
        api_key = auth_cfg.get("api_key") or data.get("api_key")
        credential_ref = auth_cfg.get("credential_ref") or data.get("credential_ref")
        header_name = auth_cfg.get("header_name") or cfg.get("auth", {}).get("api_key", {}).get(
            "header_name", "X-API-Key"
        )
        if not api_key and not credential_ref:
            # Unchanged: no credential at all still means "this device needs no auth", which
            # is a legitimate registration and must not become an error now that a second
            # way of supplying one exists.
            return None
        # F-43: optional non-header placement + scheme prefix.
        # ADR-0018: `credential_ref` is the by-reference form. Exclusivity and reference
        # syntax are both enforced by the handler rather than re-checked here, so the API and
        # a restore and a worker rehydrate all get the same answer — a second copy of the
        # rule in this route is how the two drift.
        try:
            return ApiKeyAuth(
                api_key=api_key,
                credential_ref=credential_ref,
                header_name=header_name,
                location=auth_cfg.get("location", "header"),
                name=auth_cfg.get("name"),
                value_prefix=auth_cfg.get("value_prefix", ""),
            )
        except ReferenceInvalid as exc:
            raise HTTPException(status_code=400, detail=f"Invalid credential_ref: {exc}")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid api_key auth: {exc}")
    if auth_type == "oauth2":
        auth_cfg = data.get("auth", {})
        oauth_defaults = cfg.get("auth", {}).get("oauth2", {})
        token_endpoint = auth_cfg.get("token_endpoint") or oauth_defaults.get("token_endpoint")
        client_id = auth_cfg.get("client_id") or oauth_defaults.get("client_id")
        client_secret = auth_cfg.get("client_secret") or oauth_defaults.get("client_secret")
        client_secret_ref = auth_cfg.get("client_secret_ref") or oauth_defaults.get("client_secret_ref")
        password_ref = auth_cfg.get("password_ref")
        scopes = auth_cfg.get("scopes") or oauth_defaults.get("scopes", ["read"])
        if not token_endpoint or not client_id or not (client_secret or client_secret_ref):
            raise HTTPException(
                status_code=400,
                detail=(
                    "oauth2 requires token_endpoint, client_id, and either client_secret or "
                    "client_secret_ref (ADR-0018)"
                ),
            )
        # SSRF-2: the gateway POSTs the client_secret to token_endpoint, so it is an
        # outbound device target too — run it through the same URL policy as base_url/
        # spec_url. Without this a devices:write caller could exfiltrate the secret to
        # an internal/metadata address (F-02/F-29).
        _check_target_url(token_endpoint, "token_endpoint", allow_private, allowed_ports)
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
                client_secret_ref=client_secret_ref,
                password_ref=password_ref,
            )
        except ReferenceInvalid as exc:
            # Named apart from a generic ValueError so the operator is told the reference is
            # malformed rather than hunting through the rest of the oauth2 block.
            raise HTTPException(status_code=400, detail=f"Invalid credential reference: {exc}")
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
    allowed_ports = resolve_allowed_ports(cfg)
    hostname = data.get("hostname")
    base_url = data.get("base_url")

    if not hostname or not base_url:
        raise HTTPException(status_code=400, detail="hostname and base_url required")
    # All body validation happens before the existence check, so a malformed or
    # unsupported request is rejected without a registry round-trip. The gates are the
    # shared ones (F-67) — the same call restore makes, so neither path can drift.
    transport = data.get("transport") or cfg.get("transport", {}).get("default", "sse")
    spec_url = data.get("spec_url")
    upstream_kind, upstream_transport = _read_upstream(data)
    # Built BEFORE the gates, not after, so `validate_device_registration` can see the
    # credential form (ADR-0018 §1). `_parse_auth` raises its own 400s for a malformed
    # credential, which is the same class of refusal and no less appropriate first.
    auth = _parse_auth(data, cfg, allow_private, allowed_ports)
    validate_device_registration(
        hostname=hostname,
        base_url=base_url,
        spec_url=spec_url,
        transport=transport,
        upstream_kind=upstream_kind,
        upstream_transport=upstream_transport,
        declared=set(data.keys()),
        allow_private=allow_private,
        allowed_ports=allowed_ports,
        auth=auth,
        require_references=require_references(cfg),
    )
    rate_limit_rps = _parse_rate_limit(data)

    existing = await reg.get_device(hostname)
    if existing:
        raise HTTPException(status_code=409, detail=f"Device '{hostname}' already registered; use PUT to update")

    device_cfg = await reg.register_device(
        hostname=hostname,
        base_url=base_url,
        spec_url=spec_url,
        auth=auth,
        transport=transport,
        rate_limit_rps=rate_limit_rps,
        upstream_kind=upstream_kind,
        upstream_transport=upstream_transport,
    )

    # ADR-0015 §8: an operator may supply the SPKI they verified out of band, which turns
    # trust-on-first-use into real verification for the devices where it is worth the
    # effort. Implemented as PRE-PINNING rather than as a check: writing it as the pinned
    # key means the ordinary comparison path handles everything from there — the first
    # probe that sees a different key classifies as key_changed and quarantines, with no
    # separate code path to get wrong and no TOFU window at all.
    expected_spki = data.get("expected_tls_spki_sha256")
    if expected_spki:
        expected_spki = str(expected_spki).strip().lower()
        if not _SPKI_RE.fullmatch(expected_spki):
            raise HTTPException(
                status_code=400,
                detail="expected_tls_spki_sha256 must be a 64-character hex SHA-256 digest",
            )
        await reg._backend.update_device_fields(
            hostname,
            tls_spki_sha256=expected_spki,
            fingerprint_state=fp.STATE_PINNED,
            fingerprint_pinned_at=time.time(),
        )
        # Re-read to return the stored truth rather than a locally patched copy. Keep the
        # pre-update record if it has vanished — a delete racing a registration is not a
        # reason to fail the registration that just succeeded.
        device_cfg = await reg.get_device(hostname) or device_cfg

    fingerprint_policy = data.get("fingerprint_policy")
    if fingerprint_policy:
        if str(fingerprint_policy).lower() not in (fp.POLICY_WARN, fp.POLICY_ENFORCE):
            raise HTTPException(
                status_code=400,
                detail=f"fingerprint_policy must be '{fp.POLICY_WARN}' or '{fp.POLICY_ENFORCE}'",
            )
        await reg._backend.update_device_fields(hostname, fingerprint_policy=str(fingerprint_policy).lower())
        device_cfg = await reg.get_device(hostname) or device_cfg

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
    allowed_ports = resolve_allowed_ports(cfg)
    existing = await reg.get_device(hostname)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")

    data = await request.json()
    base_url = data.get("base_url") or existing.base_url
    spec_url = data.get("spec_url", existing.spec_url)
    # Re-validate target URLs on update (a PUT can change base_url/spec_url) — Tier-0 F-02.
    _check_target_url(base_url, "base_url", allow_private, allowed_ports)
    _check_target_url(spec_url, "spec_url", allow_private, allowed_ports)

    _AUTH_KEYS = {"auth_type", "auth", "api_key"}
    auth: AbstractAuth | None = None
    keep_auth = False
    if _AUTH_KEYS & data.keys():
        auth = _parse_auth(data, cfg, allow_private, allowed_ports)
        # Gated only when the PUT actually SUPPLIES a credential. A `keep_auth` update carries
        # the stored one through untouched, and refusing that would block an ordinary edit —
        # a rate-limit change — on every device registered before references existed. The
        # promise is that existing devices keep working; only new credentials are refused.
        check_credential_form(auth, require_references(cfg))
    else:
        # No auth field in the PUT body → preserve the stored credentials. We must
        # NOT reconstruct them here: in distributed mode existing.auth_config is
        # Fernet ciphertext, and parsing it as JSON failed and silently wiped the
        # device's credentials. Let the registry carry the stored record verbatim.
        keep_auth = True
    transport = data.get("transport") or existing.transport
    _validate_transport(transport)
    rate_limit_rps = _parse_rate_limit(data)
    upstream_kind, upstream_transport = _read_upstream(data, existing.upstream_kind, existing.upstream_transport)
    _validate_upstream(upstream_kind, upstream_transport, spec_url, declared=set(data.keys()))

    device_cfg = await reg.replace_device(
        hostname=hostname,
        base_url=base_url,
        spec_url=spec_url,
        auth=auth,
        transport=transport,
        rate_limit_rps=rate_limit_rps,
        keep_auth=keep_auth,
        upstream_kind=upstream_kind,
        upstream_transport=upstream_transport,
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
        upstream_kind=device.upstream_kind,
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
        # Resolved from config, not from the device record — the same resolution the
        # spec fetcher and the pod use, so this reports what the gateway would actually
        # present/trust rather than a separate description of it that can drift.
        tls=TlsProfileInfo(**reg.tls_profile_for(hostname)),
    )


@router.post(
    "/devices/{hostname}/fingerprint/approve",
    dependencies=[
        Depends(require_scope(SCOPE_DEVICES_WRITE)),
        Depends(rate_limit("30/minute", "fingerprint_approve")),
    ],
    summary="Approve a changed endpoint fingerprint",
)
async def approve_fingerprint(hostname: str, request: Request):
    """Re-pin a device to the key it is now presenting (ADR-0015 §6).

    Approval is a **trust decision**, not a dismissal, so it is audited with the principal
    and both key values. `devices:write` is the scope by decision (§9): the operator who
    registers devices is the one who knows whether a changed endpoint is still the right
    one, and the gateway's RBAC is deliberately small. The trade-off is explicit — this is
    not separation of duty, and the audit record is what carries the accountability.
    """
    reg: Registry = request.app.state.registry
    device = await reg.get_device(hostname)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found")

    if device.fingerprint_state != fp.STATE_PENDING:
        # Not an error worth failing loudly on, but not a silent success either: approving
        # a device that is not pending means the operator is looking at stale information.
        raise HTTPException(
            status_code=409,
            detail=(
                f"Device '{hostname}' has no fingerprint change awaiting approval "
                f"(state: {device.fingerprint_state})"
            ),
        )
    if not device.pending_tls_spki_sha256:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Device '{hostname}' is pending approval but records no pending key; "
                "re-probe the device before approving"
            ),
        )

    previous = device.tls_spki_sha256
    fields = fp.approve(device.pending_tls_spki_sha256, time.time())
    await reg._backend.update_device_fields(hostname, **fields)

    # Both values in the record: an audit entry saying only "approved" cannot answer the
    # question someone will actually ask later, which is what it changed FROM.
    audit_request(
        request,
        "device.fingerprint.approve",
        outcome=AUDIT_OUTCOME_SUCCESS,
        target=hostname,
        detail=f"spki {(previous or 'none')[:16]} -> {device.pending_tls_spki_sha256[:16]}",
    )
    updated = await reg.get_device(hostname)
    if updated is None:
        # Deleted between the approval write and this read. The approval itself is already
        # audited above, so report the race rather than inventing a device to return.
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' was removed during approval")
    return DeviceMutationResult(
        status="fingerprint_approved",
        provisioning=False,
        device=DeviceDetail.from_config(updated),
    )
