from __future__ import annotations

import inspect

from ghidra_headless_mcp.backend import GhidraBackend
from ghidra_headless_mcp.fake_ghidra import FakeGhidraBackend
from ghidra_headless_mcp.server import BACKEND_TOOL_SPECS, SimpleMcpServer


def test_tool_registry_and_definitions_match() -> None:
    server = SimpleMcpServer(FakeGhidraBackend())
    handler_names = set(server._tool_handlers)
    definition_names = {item["name"] for item in server._tool_definitions()}
    assert handler_names == definition_names


def test_backend_methods_exposed_by_tools_without_dead_public_api() -> None:
    backend_methods = {
        name
        for name, member in inspect.getmembers(GhidraBackend, inspect.isfunction)
        if not name.startswith("_")
    }
    exposed_backend_methods = {spec["backend_method"] for spec in BACKEND_TOOL_SPECS}

    missing_backend_methods = sorted(exposed_backend_methods - backend_methods)
    assert not missing_backend_methods, "tools reference missing backend methods: " + ", ".join(
        missing_backend_methods
    )

    dead_backend_methods = sorted(backend_methods - exposed_backend_methods - {"shutdown", "ping"})
    if any(spec["name"].startswith("program.") for spec in BACKEND_TOOL_SPECS):
        assert not dead_backend_methods, (
            "backend public methods not reachable by tools: " + ", ".join(dead_backend_methods)
        )
        return

    transitional_prefixes = (
        "bookmark_",
        "class_",
        "comment_",
        "context_",
        "decomp_",
        "equate_",
        "external_",
        "function_body_",
        "function_calling_",
        "function_flags_",
        "function_thunk_",
        "layout_",
        "listing_",
        "namespace_",
        "parameter_",
        "project_",
        "reference_",
        "relocation_",
        "source_",
        "stackframe_",
        "symbol_",
        "tag_",
        "transaction_",
        "type_archives_",
        "type_category_",
        "type_get_by_id",
        "type_source_archives_",
        "variable_",
    )
    transitional_methods = {"project_search_programs", "stackframe_variables"}
    unexpected_dead_methods = [
        name
        for name in dead_backend_methods
        if not name.startswith(transitional_prefixes) and name not in transitional_methods
    ]
    assert not unexpected_dead_methods, (
        "backend public methods not reachable by tools: " + ", ".join(unexpected_dead_methods)
    )


def test_tool_names_are_unique() -> None:
    tool_names = [spec["name"] for spec in BACKEND_TOOL_SPECS]
    assert len(tool_names) == len(set(tool_names))


def test_canonical_category_families_replace_legacy_prefixes_when_present() -> None:
    tool_names = [spec["name"] for spec in BACKEND_TOOL_SPECS]
    canonical_roots = (
        "program.",
        "project.",
        "transaction.",
        "listing.",
        "symbol.",
        "reference.",
        "comment.",
        "function.",
        "type.",
        "layout.",
        "decomp.",
        "graph.",
    )
    if not any(name.startswith("program.") for name in tool_names):
        return

    for root in canonical_roots:
        assert any(name.startswith(root) for name in tool_names), root

    legacy_roots = (
        "session.",
        "binary.",
        "annotation.",
        "xref.",
        "undo.",
        "disasm.",
        "cfg.",
        "callgraph.",
        "struct.",
        "enum.",
        "data.",
    )
    assert not [name for name in tool_names if name.startswith(legacy_roots)]


def _array_without_items(schema: object, path: str, issues: list[str]) -> None:
    if not isinstance(schema, dict):
        return
    type_field = schema.get("type")
    types = (
        [type_field]
        if isinstance(type_field, str)
        else [item for item in type_field if isinstance(item, str)]
        if isinstance(type_field, list)
        else []
    )
    if (
        "array" in types
        and "items" not in schema
        and not (schema.get("oneOf") or schema.get("anyOf"))
    ):
        issues.append(path)

    for combinator in ("oneOf", "anyOf", "allOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for index, branch in enumerate(branches):
                _array_without_items(branch, f"{path}.{combinator}[{index}]", issues)

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, subschema in properties.items():
            _array_without_items(subschema, f"{path}.{name}", issues)

    items = schema.get("items")
    if isinstance(items, dict):
        _array_without_items(items, f"{path}.items", issues)


def test_array_schemas_declare_items() -> None:
    """Strict JSON Schema clients reject array schemas without `items`."""
    server = SimpleMcpServer(FakeGhidraBackend())
    issues: list[str] = []
    for tool in server._tool_definitions():
        _array_without_items(tool["inputSchema"], tool["name"], issues)
    assert not issues, "array schemas missing 'items': " + ", ".join(issues)
