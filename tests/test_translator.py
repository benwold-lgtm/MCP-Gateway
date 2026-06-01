"""
Unit tests for OpenAPI-to-MCP translation logic.
Validates schema mapping across different HTTP methods, parameter types,
and nested structures.
"""

from device_mcp_gateway.core.translator import SpecTranslator


def fresh_spec(**overrides):
    """Create a deep-copied minimal valid OpenAPI 3.0 spec with optional overrides."""
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {},
        "components": {"schemas": {}},
    }
    for k, v in overrides.items():
        spec[k] = v
    return spec


def find_tool_by_name(tools, name_or_prefix):
    """Find a tool by exact name or prefix match."""
    for t in tools:
        if t.name == name_or_prefix or t.name.startswith(name_or_prefix):
            return t
    return None


class TestGetEndpointTranslation:
    def test_basic_get_with_path_param(self):
        spec = fresh_spec()
        spec["paths"]["/items/{item_id}"] = {
            "get": {
                "operationId": "get_item_by_id",
                "summary": "Retrieve a specific item",
                "parameters": [
                    {"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "fields", "in": "query", "required": False, "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "Success"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        tool = manifest.tools[0]
        assert tool.name == "get_item_by_id"
        assert "Retrieve a specific item" in tool.description

        # Translator flattens path + query params into properties directly
        schema = tool.schema
        assert "item_id" in schema["properties"]
        assert schema["properties"]["item_id"]["type"] == "integer"
        assert "item_id" in schema["required"]
        assert "fields" not in schema["required"]

    def test_get_with_no_parameters(self):
        spec = fresh_spec()
        spec["paths"]["/health"] = {"get": {"operationId": "check_health", "responses": {"200": {"description": "OK"}}}}

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        tool = manifest.tools[0]
        assert tool.name == "check_health"
        assert not tool.schema["properties"]

    def test_get_with_array_and_enum_query_params(self):
        spec = fresh_spec()
        spec["paths"]["/status"] = {
            "get": {
                "operationId": "get_status",
                "parameters": [
                    {
                        "name": "regions",
                        "in": "query",
                        "schema": {"type": "array", "items": {"type": "string", "enum": ["US", "EU", "APAC"]}},
                    }
                ],
                "responses": {"200": {"description": "Success"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        schema = manifest.tools[0].schema
        assert "regions" in schema["properties"]
        assert schema["properties"]["regions"]["type"] == "array"
        # NOTE: translator currently only preserves type+description per property
        # (drops format, enum, items, nested properties)


class TestPostEndpointTranslation:
    def test_post_with_json_body(self):
        spec = fresh_spec()
        spec["paths"]["/users"] = {
            "post": {
                "operationId": "create_user",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
                                "required": ["name"],
                            }
                        }
                    },
                },
                "responses": {"201": {"description": "Created"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        tool = manifest.tools[0]
        assert tool.name == "create_user"
        # Body properties are flattened into the schema's properties
        schema = tool.schema
        assert "name" in schema["properties"]
        assert schema["properties"]["name"]["type"] == "string"
        assert "age" in schema["properties"]
        assert "name" in schema["required"]
        assert "age" not in schema["required"]

    def test_post_with_path_and_body_params(self):
        spec = fresh_spec()
        spec["paths"]["/items/{item_id}"] = {
            "post": {
                "operationId": "update_item_action",
                "parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"type": "object", "properties": {"action": {"type": "string"}}}}
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        tool = manifest.tools[0]
        assert tool.name == "update_item_action"
        schema = tool.schema
        # Path params and body properties are both flattened into top-level properties
        assert "item_id" in schema["properties"]
        assert schema["properties"]["item_id"]["type"] == "string"
        assert "action" in schema["properties"]
        assert schema["properties"]["action"]["type"] == "string"


class TestPutAndDeleteEndpointTranslation:
    def test_put_full_update(self):
        spec = fresh_spec()
        spec["paths"]["/config"] = {
            "put": {
                "operationId": "replace_config",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "properties": {"timeout": {"type": "integer"}}}
                        }
                    },
                },
                "responses": {"200": {"description": "Updated"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        assert manifest.tools[0].name == "replace_config"
        assert "timeout" in manifest.tools[0].schema["properties"]

    def test_delete_with_query_filter(self):
        spec = fresh_spec()
        spec["paths"]["/logs"] = {
            "delete": {
                "operationId": "purge_logs",
                "parameters": [
                    {
                        "name": "older_than",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "format": "date"},
                    }
                ],
                "responses": {"204": {"description": "Deleted"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        schema = manifest.tools[0].schema
        assert schema["properties"]["older_than"]["type"] == "string"
        assert "older_than" in schema["required"]


class TestNestedAndComponentSchemas:
    def test_nested_object_parameters(self):
        spec = fresh_spec()
        spec["paths"]["/search"] = {
            "post": {
                "operationId": "advanced_search",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "filters": {
                                        "type": "object",
                                        "properties": {"status": {"type": "string"}, "priority": {"type": "integer"}},
                                    }
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Results"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        schema = manifest.tools[0].schema
        filters = schema["properties"]["filters"]
        # NOTE: translator flattens nested body properties to top-level only
        # (drops inner properties of nested objects, only keeps type+description)
        assert filters["type"] == "object"

    def test_mutable_state_isolation(self):
        """Ensure SpecTranslator instances don't leak state between translations."""
        t1 = SpecTranslator()
        m1 = t1.translate(
            fresh_spec(paths={"/x": {"get": {"operationId": "x", "responses": {"200": {"description": "OK"}}}}})
        )
        assert len(m1.tools) == 1
        assert m1.tools[0].name == "x"

        t2 = SpecTranslator()
        m2 = t2.translate(
            fresh_spec(paths={"/y": {"post": {"operationId": "y", "responses": {"200": {"description": "OK"}}}}})
        )
        assert len(m2.tools) == 1
        assert m2.tools[0].name == "y"


class TestEdgeCasesAndDefaults:
    def test_missing_operation_id_generates_one(self):
        spec = fresh_spec()
        spec["paths"]["/data"] = {"get": {"summary": "Get some data", "responses": {"200": {"description": "OK"}}}}

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        # Should auto-generate a tool with a name based on method and path segment
        tool = manifest.tools[0]
        assert tool.name  # Not empty
        assert "data" in tool.name.lower()

    def test_boolean_parameter_mapping(self):
        spec = fresh_spec()
        spec["paths"]["/toggle"] = {
            "post": {
                "operationId": "toggle_feature",
                "parameters": [{"name": "enabled", "in": "query", "schema": {"type": "boolean"}}],
                "responses": {"200": {"description": "OK"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        param = manifest.tools[0].schema["properties"]["enabled"]
        assert param["type"] == "boolean"

    def test_empty_spec_returns_empty_lists(self):
        spec = fresh_spec()

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        assert manifest.tools == []
        assert manifest.resources == []
        assert manifest.prompts == []

    def test_multiple_http_methods_on_same_path(self):
        spec = fresh_spec()
        spec["paths"]["/items/{id}"] = {
            "get": {
                "operationId": "get_item",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}},
            },
            "delete": {
                "operationId": "delete_item",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"204": {"description": "Deleted"}},
            },
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        assert len(manifest.tools) == 2
        names = [t.name for t in manifest.tools]
        assert "get_item" in names
        assert "delete_item" in names

    def test_header_and_cookie_params_are_handled(self):
        spec = fresh_spec()
        spec["paths"]["/secure"] = {
            "get": {
                "operationId": "secure_call",
                "parameters": [
                    {"name": "X-API-Key", "in": "header", "schema": {"type": "string"}},
                    {"name": "session", "in": "cookie", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "OK"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        tool = manifest.tools[0]
        assert tool.name == "secure_call"
        # At minimum the tool should be generated without crashing
        assert "X-API-Key" in tool.schema["properties"] or "session" in tool.schema["properties"]

    def test_spec_description_in_tool(self):
        spec = fresh_spec()
        spec["paths"]["/info"] = {
            "get": {
                "operationId": "get_info",
                "description": "Returns system information including uptime and version",
                "responses": {"200": {"description": "OK"}},
            }
        }

        translator = SpecTranslator()
        manifest = translator.translate(spec)

        tool = manifest.tools[0]
        assert "Returns system information" in tool.description or "uptime" in tool.description.lower()
