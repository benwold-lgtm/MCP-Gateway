# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Device-type curation routes (ADR-0020 §1, slice 1).

A device type is a **template, not an instance**: it names no host, holds no credential, and
belongs to no tenant. Curating one writes to this service's own storage only — there is no
code path from here into any tenant's registry (that's the claim flow, slice 4, and it lives
entirely in the console BFF + the gateway's own `POST /v1/devices`, never here).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import require_api_token
from .repo import DeviceTypeNotFound, DeviceTypeRepo, SlugAlreadyExists
from .schemas import CreateDeviceType, DeviceTypeDetail, DeviceTypeListResponse, DeviceTypeVersion, VersionFields

router = APIRouter(dependencies=[Depends(require_api_token)])


def _repo(request: Request) -> DeviceTypeRepo:
    return DeviceTypeRepo(request.app.state.db)


@router.post("/device-types", response_model=DeviceTypeDetail, status_code=201)
async def create_device_type(fields: CreateDeviceType, request: Request):
    try:
        return await _repo(request).create_device_type(fields)
    except SlugAlreadyExists:
        raise HTTPException(status_code=409, detail=f"a device type with slug '{fields.slug}' already exists")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/device-types/{type_id}/versions", response_model=DeviceTypeVersion, status_code=201)
async def add_device_type_version(type_id: uuid.UUID, fields: VersionFields, request: Request):
    try:
        return await _repo(request).add_version(type_id, fields)
    except DeviceTypeNotFound:
        raise HTTPException(status_code=404, detail=f"no device type '{type_id}'")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/device-types", response_model=DeviceTypeListResponse)
async def list_device_types(request: Request):
    return DeviceTypeListResponse(device_types=await _repo(request).list_device_types())


@router.get("/device-types/{type_id}", response_model=DeviceTypeDetail)
async def get_device_type(type_id: uuid.UUID, request: Request):
    result = await _repo(request).get_device_type(type_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"no device type '{type_id}'")
    return result
