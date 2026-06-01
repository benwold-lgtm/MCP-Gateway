"""
OpenAPI 3.0/3.1 -> MCP Manifest Translator

Converts an OpenAPI spec dict into:
  - MCP Tools (executable operations with JSON schema parameters)
  - MCP Resources (read-only data endpoints)
  - MCP Prompts (natural-language descriptions of what the device does)
"""

from dataclasses import dataclass, field
from typing import Any

from loguru import logger
from openapi_spec_validator import validate as _validate_openapi_spec
from openapi_spec_validator.validation.exceptions import OpenAPISpecValidatorError


@dataclass
class McpTool:
    """MCP tool representation."""
    name: str
    description: str
    schema: dict[str, Any]
    method: str          # GET, POST, PUT, DELETE, PATCH
    path: str
    tags: list[str] = field(default_factory=list)


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

    def translate(self, spec: dict, hostname: str = "test-device") -> dict:
        """Main entry point: spec dict + hostname -> McpManifest."""
        try:
            _validate_openapi_spec(spec)
        except OpenAPISpecValidatorError as exc:
            raise ValueError(f"Invalid OpenAPI spec: {exc}") from exc
        info = spec.get("info", {})
        manifest = McpManifest(
            server_name=f"mcp-{hostname}",
            server_version=info.get("version", "v1"),
            hostname=hostname,
            metadata={
                "title": info.get("title", hostname),
                "description": info.get("description", ""),
                "openapi_version": spec.get("openapi", "?"),
            },
        )
        paths = spec.get("paths", {})
        components = spec.get("components", {})
        schemas = components.get("schemas", {})
        for path, methods in paths.items():
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    continue
                tool = self._build_tool(method, path, op, schemas, hostname)
                if tool:
                    manifest.tools.append(tool)
                if method.upper() == "GET":
                    resource = self._build_resource(path, op, hostname)
                    if resource:
                        manifest.resources.append(resource)
        manifest.prompts = self._build_prompts(spec, manifest)
        logger.info(f"Translated {len(manifest.tools)} tools, "
                     f"{len(manifest.resources)} resources, "
                     f"{len(manifest.prompts)} prompts for {hostname}")
        return manifest

    # ---- Tool Building ----

    def _build_tool(self, method: str, path: str, op: dict,
                    schemas: dict, hostname: str) -> McpTool | None:
        """Convert a single OpenAPI operation into an MCP tool."""
        op_id = op.get("operationId", "")
        name = _sanitize_name(op_id or f"{method}_{path}")
        description = op.get("summary") or op.get("description") or f"{method} {path}"
        parameters, required = self._build_parameter_schema(op, schemas)
        tags = op.get("tags", [])
        return McpTool(
            name=name,
            description=description or f"{method} {path}",
            schema={"type": "object", "properties": parameters, "required": required},
            method=method.upper(),
            path=path,
            tags=tags,
        )

    def _build_parameter_schema(self, op: dict, schemas: dict) -> tuple[dict[str, Any], list[str]]:
        """Extract JSON-serializable parameter schema from an operation."""
        params = {}
        for param in op.get("parameters", []):
            pname = param.get("name", "")
            ptype = "string"
            if param.get("in") == "body" or param.get("in") == "cookie":
                continue
            schema = param.get("schema", {})
            stype = schema.get("type", "string")
            if stype == "integer":
                ptype = "integer"
            elif stype == "number":
                ptype = "number"
            elif stype == "boolean":
                ptype = "boolean"
            elif stype == "array":
                ptype = "array"
            elif stype == "object":
                ptype = "object"
            param_desc = param.get("description", "")
            params[pname] = {"type": ptype, "description": param_desc}
        req = [p.get("name") for p in op.get("parameters", []) if p.get("required")]
        body = op.get("requestBody", {})
        if body:
            content = body.get("content", {})
            for ctype, cschema in content.items():
                if cschema and "schema" in cschema:
                    props = cschema["schema"].get("properties", {})
                    for k, v in props.items():
                        params[k] = {"type": v.get("type", "string"),
                                     "description": v.get("description", "")}
                    req += [k for k in cschema["schema"].get("required", [])]
        return params, req

    # ---- Resource Building ----

    def _build_resource(self, path: str, op: dict, hostname: str) -> McpResource | None:
        """Convert a GET operation into a read-only MCP resource."""
        desc = op.get("description", "") or op.get("summary", "") or f"Resource at {path}"
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
            prompts.append(McpPrompt(
                name=f"what_is_{_sanitize_name(title)}",
                description=f"Describe what {title} does",
                template=f"You are given access to a device API called '{title}'. "
                         f"Context: {desc}\n\n"
                         f"Available tools: {[t.name for t in manifest.tools]}",
            ))
        return prompts
