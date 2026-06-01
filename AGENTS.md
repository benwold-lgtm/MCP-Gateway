# Hermes Agent Instructions for device-mcp-gateway

## Location
This file is the authoritative agent guide for this repository.
Place it at the repository root: `/mnt/labfiles/projects/device-mcp-gateway/AGENTS.md`.

## Canonical implementation
Use `device_mcp_gateway/main.py` as the canonical gateway entrypoint.
The repository has been cleaned so that the active implementation path is:
- `device_mcp_gateway/main.py`
- `device_mcp_gateway/registry/server.py`
- `device_mcp_gateway/core/translator.py`
- `device_mcp_gateway/pods/device_pod.py`
- `device_mcp_gateway/auth/`
- `device_mcp_gateway/cfg/settings.py`
- `device_mcp_gateway/logging/setup.py`

Legacy scaffold files such as `device_mcp_gateway/core/schemas.py` and
`device_mcp_gateway/registry/manager.py` have been removed from the active
implementation.

## Project purpose
This repository implements a Device MCP Gateway that:
- discovers OpenAPI/Swagger specs from registered devices,
- translates those specs into MCP tools/resources/prompts,
- spawns one isolated MCP pod per device hostname,
- routes LLM tool invocations through the gateway to target APIs,
- supports SSE, stdio, and HTTP transports,
- supports API key and OAuth2-based auth.

## Work scope
1. Only change files inside this repository, especially under `device_mcp_gateway/`, `tests/`, and root config files.
2. Follow `README.md` as the functional architecture spec.
3. Focus on the existing implementation architecture, not on inventing new gateway models.
4. Do not mark work complete until code is updated and validated by tests.
5. If a task is blocked because of missing information or environment data, ask for clarification.

## Key modules
- `device_mcp_gateway/main.py` — FastAPI entrypoint and lifecycle
- `device_mcp_gateway/registry/server.py` — device registration, spec discovery, health checks, pod lifecycle
- `device_mcp_gateway/core/translator.py` — OpenAPI → MCP manifest translation
- `device_mcp_gateway/pods/device_pod.py` — pod startup, tool registration, request proxying
- `device_mcp_gateway/pods/transport/` — transport adapters
- `device_mcp_gateway/auth/` — auth header and token handling

## Acceptance criteria
- `/devices` registration works and returns a registered device list.
- `/health` and `/metrics` reflect gateway status correctly.
- OpenAPI spec discovery and caching behave correctly.
- Pods are spawned cleanly and do not leave dangling tasks.
- Auth headers/token handling are applied before proxying requests.
- Relevant tests pass.

## Strict agent rules
- Do not guess missing API behavior. If uncertain, stop and ask.
- Prefer small, incremental changes over broad refactors.
- Keep implementation aligned with `README.md` and existing module design.
- Use tests to verify every non-trivial change.
- Always validate changes by checking the repository and running tests.
