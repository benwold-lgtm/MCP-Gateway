# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""
OpenAPI 3.0/3.1 -> MCP Manifest Translator

Converts an OpenAPI spec dict into:
  - MCP Tools (executable operations with JSON schema parameters)
  - MCP Resources (read-only data endpoints)
  - MCP Prompts (natural-language descriptions of what the device does)
"""

import re
from dataclasses import dataclass, field
from typing import Any

from loguru import logger
from openapi_spec_validator import validate as _validate_openapi_spec
from openapi_spec_validator.validation.exceptions import OpenAPISpecValidatorError

# Device-supplied spec text (summaries/descriptions/titles) becomes LLM-facing tool
# metadata, so it is untrusted (Tier-0 F-26 — schema poisoning / indirect prompt
# injection). Strip control chars, Unicode bidi overrides, and zero-width characters —
# all used to hide injected instructions — and length-cap. This removes obfuscation
# vectors and bounds size; it does not (and cannot, in the gateway) neutralize plain
# semantic injection, so the LLM client should still treat tool descriptions as
# untrusted, device-provided content.
_UNSAFE_TEXT_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f" "\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_MAX_DESC_LEN = 1024


def _sanitize_text(text: str | None, max_len: int = _MAX_DESC_LEN) -> str:
    """Strip obfuscation characters and cap length on untrusted spec text (Tier-0 F-26)."""
    if not text:
        return ""
    cleaned = _UNSAFE_TEXT_RE.sub("", text)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1].rstrip() + "…"
    return cleaned


@dataclass
class McpTool:
    """MCP tool representation."""

    name: str
    description: str
    schema: dict[str, Any]
    method: str  # GET, POST, PUT, DELETE, PATCH
    path: str
    tags: list[str] = field(default_factory=list)
    param_locations: dict[str, str] = field(default_factory=dict)


@dataclass
class McpResource:
    """MCP resource representation."""

    uri: str
    name: str
    description: str
    mime_type: str = "application/json"


@dataclass
class McpPrompt:
    """MCP prompt template."""

    name: str
    description: str
    template: str
    arguments: list[str] = field(default_factory=list)


@dataclass
class McpManifest:
    """Complete MCP server manifest for a single device/API."""

    server_name: str
    server_version: str
    hostname: str
    tools: list[McpTool] = field(default_factory=list)
    resources: list[McpResource] = field(default_factory=list)
    prompts: list[McpPrompt] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def _sanitize_name(raw: str) -> str:
    """Convert a path segment or operationId into a valid MCP tool name."""
    import re

    name = re.sub(r"[^a-zA-Z0-9_]", "_", raw.strip("/"))
    name = re.sub(r"_+", "_", name)
    return name.lower().strip("_")


class SpecTranslator:
    """Translates OpenAPI specs into MCP manifests."""

    def __init__(self) -> None:
        self._spec: dict[str, Any] = {}

    def translate(self, spec: dict, hostname: str = "test-device") -> McpManifest:
        """Main entry point: spec dict + hostname -> McpManifest."""
        try:
            _validate_openapi_spec(spec)
        except OpenAPISpecValidatorError as exc:
            raise ValueError(f"Invalid OpenAPI spec: {exc}") from exc
        self._spec = spec  # stored so _resolve_ref can walk the full document
        info = spec.get("info", {})
        manifest = McpManifest(
            server_name=f"mcp-{hostname}",
            server_version=info.get("version", "v1"),
            hostname=hostname,
            metadata={
                "title": _sanitize_text(info.get("title", hostname)),
                "description": _sanitize_text(info.get("description", "")),
                "openapi_version": spec.get("openapi", "?"),
            },
        )
        paths = spec.get("paths", {})
        _used_names: set[str] = set()
        for path, methods in paths.items():
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    continue
                tool = self._build_tool(method, path, op, hostname)
                if tool:
                    if tool.name in _used_names:
                        base = tool.name
                        n = 2
                        while f"{base}_{n}" in _used_names:
                            n += 1
                        new_name = f"{base}_{n}"
                        logger.warning(
                            f"Tool name collision: '{tool.name}' "
                            f"(operation: {op.get('operationId') or f'{method} {path}'})"
                            f" renamed to '{new_name}'"
                        )
                        tool.name = new_name
                    _used_names.add(tool.name)
                    manifest.tools.append(tool)
                if method.upper() == "GET":
                    resource = self._build_resource(path, op, hostname)
                    if resource:
                        manifest.resources.append(resource)
        manifest.prompts = self._build_prompts(spec, manifest)
        logger.info(
            f"Translated {len(manifest.tools)} tools, "
            f"{len(manifest.resources)} resources, "
            f"{len(manifest.prompts)} prompts for {hostname}"
        )
        return manifest

    # ---- Tool Building ----

    def _build_tool(self, method: str, path: str, op: dict, hostname: str) -> McpTool | None:
        """Convert a single OpenAPI operation into an MCP tool."""
        op_id = op.get("operationId", "")
        name = _sanitize_name(op_id or f"{method}_{path}")
        # Tool description is device-supplied and shown to the LLM → untrusted (F-26).
        description = _sanitize_text(op.get("summary") or op.get("description") or f"{method} {path}")
        parameters, required, locations = self._build_parameter_schema(op)
        tags = op.get("tags", [])
        return McpTool(
            name=name,
            description=description or f"{method} {path}",
            schema={"type": "object", "properties": parameters, "required": required},
            method=method.upper(),
            path=path,
            tags=tags,
            param_locations=locations,
        )

    def _resolve_ref(self, ref: str) -> dict:
        """Walk a JSON Pointer ($ref) from the spec root.

        Supports any internal ref (#/...) including components/schemas,
        components/parameters, components/requestBodies, etc.
        Logs a warning and returns {} for external file or URL refs.
        """
        if not ref.startswith("#/"):
            logger.warning(f"External $ref '{ref}' is not supported — using empty schema")
            return {}
        parts = ref.lstrip("#/").split("/")
        node: Any = self._spec
        for part in parts:
            if not isinstance(node, dict):
                logger.warning(f"Could not resolve $ref '{ref}'")
                return {}
            node = node.get(part)
            if node is None:
                logger.warning(f"Could not resolve $ref '{ref}' — segment '{part}' not found in spec")
                return {}
        return node if isinstance(node, dict) else {}

    def _resolve_schema(self, schema: dict, seen: set | None = None) -> dict:
        """Recursively resolve $ref, allOf/anyOf/oneOf, and nested object properties."""
        if seen is None:
            seen = set()

        if "$ref" in schema:
            ref = schema["$ref"]
            if ref in seen:
                return {"type": "object"}
            child_seen = seen | {ref}
            base = self._resolve_ref(ref)
            extra = {k: v for k, v in schema.items() if k != "$ref"}
            return self._resolve_schema({**base, **extra}, child_seen)

        if "allOf" in schema:
            result = self._merge_schemas(schema["allOf"], seen, require_all=True)
            for k, v in schema.items():
                if k != "allOf" and k not in result:
                    result[k] = v
            return result

        for combiner in ("anyOf", "oneOf"):
            if combiner in schema:
                result = self._merge_schemas(schema[combiner], seen, require_all=False)
                for k, v in schema.items():
                    if k != combiner and k not in result:
                        result[k] = v
                return result

        if schema.get("type") == "object" and "properties" in schema:
            return {
                **schema,
                "properties": {k: self._resolve_schema(v, seen) for k, v in schema["properties"].items()},
            }

        return schema

    def _merge_schemas(self, schemas: list[dict], seen: set, require_all: bool) -> dict:
        """Merge a list of sub-schemas.

        require_all=True (allOf): every schema applies — union properties, union required.
        require_all=False (anyOf/oneOf): alternatives — union properties, no required.
        """
        props: dict[str, Any] = {}
        req: list[str] = []
        base: dict[str, Any] = {}
        for sub in schemas:
            resolved = self._resolve_schema(sub, seen)
            props.update(resolved.get("properties", {}))
            if require_all:
                req.extend(resolved.get("required", []))
            for k in ("type", "description", "title"):
                if k in resolved and k not in base:
                    base[k] = resolved[k]
        result = dict(base)
        if props:
            result.setdefault("type", "object")
            result["properties"] = props
        if req:
            result["required"] = list(dict.fromkeys(req))
        return result

    def _build_parameter_schema(self, op: dict) -> tuple[dict[str, Any], list[str], dict[str, str]]:
        """Extract JSON-serializable parameter schema and per-param locations from an operation."""
        params: dict[str, Any] = {}
        locations: dict[str, str] = {}
        req: list[str] = []

        for raw_param in op.get("parameters", []):
            param = raw_param
            if "$ref" in raw_param:
                param = self._resolve_ref(raw_param["$ref"])
                if not param:
                    continue
            pname = param.get("name", "")
            if not pname:
                continue
            pin = param.get("in", "query")
            if pin in ("body", "cookie"):
                continue
            raw_schema = param.get("schema", {})
            resolved = self._resolve_schema(raw_schema)
            param_desc = param.get("description", resolved.get("description", ""))
            params[pname] = {**resolved, "description": param_desc}
            locations[pname] = pin
            if param.get("required"):
                req.append(pname)

        body = op.get("requestBody", {})
        if "$ref" in body:
            body = self._resolve_ref(body["$ref"])
        if body:
            content = body.get("content", {})
            for _ctype, cschema in content.items():
                if cschema and "schema" in cschema:
                    body_schema = self._resolve_schema(cschema["schema"])
                    for k, v in body_schema.get("properties", {}).items():
                        params[k] = self._resolve_schema(v)
                        locations[k] = "body"
                    req += list(body_schema.get("required", []))

        return params, req, locations

    # ---- Resource Building ----

    def _build_resource(self, path: str, op: dict, hostname: str) -> McpResource | None:
        """Convert a GET operation into a read-only MCP resource."""
        desc = _sanitize_text(op.get("description", "") or op.get("summary", "") or f"Resource at {path}")
        uri = f"device://{hostname}{path}"
        name = _sanitize_name(path)
        return McpResource(
            uri=uri,
            name=name,
            description=desc,
            mime_type="application/json",
        )

    # ---- Prompt Building ----

    def _build_prompts(self, spec: dict, manifest: McpManifest) -> list[McpPrompt]:
        """Generate natural-language prompt templates from spec info."""
        prompts = []
        title = manifest.metadata.get("title", manifest.hostname)
        desc = manifest.metadata.get("description", "")
        if desc:
            prompts.append(
                McpPrompt(
                    name=f"what_is_{_sanitize_name(title)}",
                    description=f"Describe what {title} does",
                    template=f"You are given access to a device API called '{title}'. "
                    f"Context: {desc}\n\n"
                    f"Available tools: {[t.name for t in manifest.tools]}",
                )
            )
        return prompts
