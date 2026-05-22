"""Resolver handles symbol names as well as addresses."""

from __future__ import annotations

import json


def _call(server, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_name_resolves_to_function_via_symbol_lookup(server, stub_backend):
    """When the agent passes a name and the resolver returns an exact hit,
    the response carries address_adjusted with reason=symbol_lookup."""
    stub_backend.next_eval_response = {
        "kind": "exact", "reason": "symbol_lookup",
        "address": "0x401234", "name": "main",
    }
    r = _call(server, "decompile", {"function_start": "main"})
    assert r["isError"] is False
    adj = r["structuredContent"]["address_adjusted"]
    assert adj == {"requested": "main", "resolved": "0x401234", "reason": "symbol_lookup"}


def test_name_not_found_returns_structured_error(server, stub_backend):
    stub_backend.next_eval_response = {
        "kind": "miss", "reason": "name_not_found",
        "is_code": False, "in_section": None, "name": "nope",
    }
    r = _call(server, "decompile", {"function_start": "nope"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "not_found_name"
    assert "search.functions" in sc["next_action"]
    assert "sm.getSymbols" in sc["pyghidra_hint"]
