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


class TestParamLocations:
    def test_path_and_query_locations(self):
        spec = fresh_spec()
        spec["paths"]["/items/{item_id}"] = {
            "get": {
                "operationId": "get_item",
                "parameters": [
                    {"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                ],
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert tool.param_locations["item_id"] == "path"
        assert tool.param_locations["verbose"] == "query"

    def test_body_params_location(self):
        spec = fresh_spec()
        spec["paths"]["/users"] = {
            "post": {
                "operationId": "create_user",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
                            }
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert tool.param_locations["name"] == "body"
        assert tool.param_locations["age"] == "body"

    def test_mixed_path_and_body_locations(self):
        spec = fresh_spec()
        spec["paths"]["/items/{item_id}"] = {
            "post": {
                "operationId": "update_item",
                "parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"type": "object", "properties": {"action": {"type": "string"}}}}
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert tool.param_locations["item_id"] == "path"
        assert tool.param_locations["action"] == "body"


class TestRefAndNestedSchemas:
    def test_ref_in_request_body_is_resolved(self):
        spec = fresh_spec()
        spec["components"]["schemas"]["CreateItem"] = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "price": {"type": "number"}},
            "required": ["name"],
        }
        spec["paths"]["/items"] = {
            "post": {
                "operationId": "create_item",
                "requestBody": {
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateItem"}}}
                },
                "responses": {"201": {"description": "Created"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "name" in tool.schema["properties"]
        assert "price" in tool.schema["properties"]
        assert "name" in tool.schema["required"]

    def test_nested_object_properties_are_preserved(self):
        spec = fresh_spec()
        spec["paths"]["/search"] = {
            "post": {
                "operationId": "search",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "filter": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "limit": {"type": "integer"},
                                        },
                                    }
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        filter_schema = tool.schema["properties"]["filter"]
        assert filter_schema["type"] == "object"
        assert "status" in filter_schema["properties"]
        assert "limit" in filter_schema["properties"]

    def test_ref_in_parameter_schema_is_resolved(self):
        spec = fresh_spec()
        spec["components"]["schemas"]["SortOrder"] = {"type": "string", "enum": ["asc", "desc"]}
        spec["paths"]["/items"] = {
            "get": {
                "operationId": "list_items",
                "parameters": [
                    {
                        "name": "sort",
                        "in": "query",
                        "schema": {"$ref": "#/components/schemas/SortOrder"},
                    }
                ],
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "sort" in tool.schema["properties"]
        assert tool.schema["properties"]["sort"]["type"] == "string"

    def test_cyclic_ref_does_not_loop(self):
        spec = fresh_spec()
        spec["components"]["schemas"]["Node"] = {
            "type": "object",
            "properties": {"child": {"$ref": "#/components/schemas/Node"}},
        }
        spec["paths"]["/tree"] = {
            "post": {
                "operationId": "create_node",
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}},
                "responses": {"201": {"description": "Created"}},
            }
        }
        # Must not raise RecursionError
        tool = SpecTranslator().translate(spec).tools[0]
        assert "child" in tool.schema["properties"]


class TestComponentRefResolution:
    def test_parameter_object_ref_is_resolved(self):
        spec = fresh_spec()
        spec["components"]["parameters"] = {
            "PageSize": {"name": "page_size", "in": "query", "required": False, "schema": {"type": "integer"}}
        }
        spec["paths"]["/items"] = {
            "get": {
                "operationId": "list_items",
                "parameters": [{"$ref": "#/components/parameters/PageSize"}],
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "page_size" in tool.schema["properties"]
        assert tool.schema["properties"]["page_size"]["type"] == "integer"
        assert tool.param_locations["page_size"] == "query"

    def test_request_body_ref_is_resolved(self):
        spec = fresh_spec()
        spec["components"]["requestBodies"] = {
            "CreateUser": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"username": {"type": "string"}, "role": {"type": "string"}},
                            "required": ["username"],
                        }
                    }
                }
            }
        }
        spec["paths"]["/users"] = {
            "post": {
                "operationId": "create_user",
                "requestBody": {"$ref": "#/components/requestBodies/CreateUser"},
                "responses": {"201": {"description": "Created"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "username" in tool.schema["properties"]
        assert "role" in tool.schema["properties"]
        assert "username" in tool.schema["required"]

    def test_required_propagated_for_parameter_ref(self):
        spec = fresh_spec()
        spec["components"]["parameters"] = {
            "DeviceId": {"name": "device_id", "in": "path", "required": True, "schema": {"type": "string"}}
        }
        spec["paths"]["/devices/{device_id}"] = {
            "get": {
                "operationId": "get_device",
                "parameters": [{"$ref": "#/components/parameters/DeviceId"}],
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "device_id" in tool.schema["required"]

    def test_external_ref_does_not_crash(self):
        spec = fresh_spec()
        spec["paths"]["/items"] = {
            "post": {
                "operationId": "create_item",
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "./other.yaml#/components/schemas/Item"}}
                    }
                },
                "responses": {"201": {"description": "Created"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert tool.name == "create_item"
        # External ref produces empty properties, but must not raise
        assert isinstance(tool.schema["properties"], dict)


class TestToolNameCollisions:
    def test_duplicate_sanitized_name_is_renamed(self):
        spec = fresh_spec()
        # /foo/bar and /foo-bar both sanitize to "get_foo_bar" (no operationId)
        spec["paths"]["/foo/bar"] = {"get": {"summary": "First", "responses": {"200": {"description": "OK"}}}}
        spec["paths"]["/foo-bar"] = {"get": {"summary": "Second", "responses": {"200": {"description": "OK"}}}}
        manifest = SpecTranslator().translate(spec)
        assert len(manifest.tools) == 2
        names = {t.name for t in manifest.tools}
        assert "get_foo_bar" in names
        assert "get_foo_bar_2" in names

    def test_three_way_collision_increments_suffix(self):
        spec = fresh_spec()
        spec["paths"]["/a/b"] = {"get": {"summary": "1", "responses": {"200": {"description": "OK"}}}}
        spec["paths"]["/a-b"] = {"get": {"summary": "2", "responses": {"200": {"description": "OK"}}}}
        spec["paths"]["/a_b"] = {"get": {"summary": "3", "responses": {"200": {"description": "OK"}}}}
        manifest = SpecTranslator().translate(spec)
        assert len(manifest.tools) == 3
        names = {t.name for t in manifest.tools}
        assert "get_a_b" in names
        assert "get_a_b_2" in names
        assert "get_a_b_3" in names

    def test_unique_names_are_not_renamed(self):
        spec = fresh_spec()
        spec["paths"]["/foo"] = {"get": {"operationId": "get_foo", "responses": {"200": {"description": "OK"}}}}
        spec["paths"]["/bar"] = {"get": {"operationId": "get_bar", "responses": {"200": {"description": "OK"}}}}
        manifest = SpecTranslator().translate(spec)
        assert len(manifest.tools) == 2
        assert {t.name for t in manifest.tools} == {"get_foo", "get_bar"}


class TestCompositionKeywords:
    def test_allof_with_component_refs_merges_properties(self):
        spec = fresh_spec()
        spec["components"]["schemas"]["Base"] = {
            "type": "object",
            "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
            "required": ["id"],
        }
        spec["paths"]["/items"] = {
            "post": {
                "operationId": "create_item",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "allOf": [
                                    {"$ref": "#/components/schemas/Base"},
                                    {
                                        "type": "object",
                                        "properties": {"extra": {"type": "string"}},
                                        "required": ["extra"],
                                    },
                                ]
                            }
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        props = tool.schema["properties"]
        assert "id" in props
        assert "name" in props
        assert "extra" in props
        assert props["id"]["type"] == "integer"
        assert "id" in tool.schema["required"]
        assert "extra" in tool.schema["required"]

    def test_allof_single_ref_is_equivalent_to_direct_ref(self):
        spec = fresh_spec()
        spec["components"]["schemas"]["Body"] = {
            "type": "object",
            "properties": {"value": {"type": "number"}},
        }
        spec["paths"]["/data"] = {
            "post": {
                "operationId": "post_data",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"allOf": [{"$ref": "#/components/schemas/Body"}]}
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "value" in tool.schema["properties"]

    def test_anyof_unions_properties_from_all_branches(self):
        spec = fresh_spec()
        spec["paths"]["/cmd"] = {
            "post": {
                "operationId": "send_cmd",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "anyOf": [
                                    {"type": "object", "properties": {"fan_speed": {"type": "integer"}}},
                                    {"type": "object", "properties": {"temperature": {"type": "number"}}},
                                ]
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        props = tool.schema["properties"]
        assert "fan_speed" in props
        assert "temperature" in props
        assert "required" not in tool.schema or not tool.schema["required"]

    def test_oneof_unions_properties_from_all_branches(self):
        spec = fresh_spec()
        spec["paths"]["/update"] = {
            "put": {
                "operationId": "update_state",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": [
                                    {"type": "object", "properties": {"mode": {"type": "string"}}, "required": ["mode"]},
                                    {"type": "object", "properties": {"level": {"type": "integer"}}},
                                ]
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        props = tool.schema["properties"]
        assert "mode" in props
        assert "level" in props
        assert "required" not in tool.schema or not tool.schema["required"]

    def test_allof_with_description_sibling_preserved(self):
        spec = fresh_spec()
        spec["components"]["schemas"]["Payload"] = {
            "type": "object",
            "properties": {"x": {"type": "integer"}},
        }
        spec["paths"]["/x"] = {
            "post": {
                "operationId": "do_x",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "description": "The payload",
                                "allOf": [{"$ref": "#/components/schemas/Payload"}],
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
        tool = SpecTranslator().translate(spec).tools[0]
        assert "x" in tool.schema["properties"]
