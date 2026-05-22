"""meta.help returns hand-written per-tool docs for all 12 tools."""

from __future__ import annotations

import json

from tinyghidramcp import meta as meta_module
from tests.test_tool_surface import EXPECTED_TOOLS


def _call(server, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "meta.help", "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_meta_docs_exist_for_every_tool():
    assert set(meta_module.DOCS.keys()) == EXPECTED_TOOLS


def test_meta_help_returns_doc_entry(server):
    r = _call(server, {"tool": "decompile"})
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["tool"] == "decompile"
    assert "function_start" in str(sc["parameters"])
    assert len(sc["examples"]) >= 1
    assert "decompAPI" in sc["pyghidra_alternative"]


def test_meta_help_unknown_tool_returns_structured_error(server):
    r = _call(server, {"tool": "no.such.tool"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "not_found_name"


def test_meta_help_missing_tool_arg(server):
    r = _call(server, {})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "tool"


def test_every_doc_has_required_fields():
    for tool, entry in meta_module.DOCS.items():
        assert "description" in entry, f"{tool} missing description"
        assert "parameters" in entry, f"{tool} missing parameters"
        assert "examples" in entry, f"{tool} missing examples"
        assert "pyghidra_alternative" in entry, f"{tool} missing pyghidra_alternative"
        assert entry["description"], f"{tool} has empty description"
