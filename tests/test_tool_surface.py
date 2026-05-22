"""Tool surface contract: tools/list returns exactly 12 tools with no session_id."""

from __future__ import annotations


EXPECTED_TOOLS = {
    "binary.summary",
    "callgraph",
    "decompile",
    "decompile.batch",
    "disassemble",
    "meta.help",
    "pyghidra.exec",
    "resolve",
    "search.functions",
    "search.strings",
    "xrefs.from",
    "xrefs.to",
}


def test_tools_list_returns_twelve(server):
    res = server._dispatch_tools_list({})
    assert res["total"] == 12
    names = {t["name"] for t in res["tools"]}
    assert names == EXPECTED_TOOLS


def test_session_id_never_appears_in_schema(server):
    res = server._dispatch_tools_list({})
    for tool in res["tools"]:
        props = tool["inputSchema"].get("properties", {})
        required = tool["inputSchema"].get("required", [])
        assert "session_id" not in props, f"{tool['name']} leaks session_id in properties"
        assert "session_id" not in required, f"{tool['name']} leaks session_id in required"


def test_every_named_tool_description_includes_pyghidra_cta(server):
    """Every tool's description should remind the agent of the escape hatch.

    Exception: `pyghidra.exec` itself doesn't need to point at itself, and
    `meta.help` already references it explicitly.
    """
    res = server._dispatch_tools_list({})
    for tool in res["tools"]:
        if tool["name"] == "pyghidra.exec":
            continue
        assert "pyghidra.exec" in tool["description"], (
            f"{tool['name']} description missing pyghidra.exec CTA"
        )
