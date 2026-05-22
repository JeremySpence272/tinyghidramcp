"""Address-tolerance pipeline behavior, driven through the dispatch layer."""

from __future__ import annotations

import json


def _call_decompile(server, addr):
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "decompile", "arguments": {"function_start": addr}},
    }
    resp = json.loads(server.handle_json_line(json.dumps(req)))
    return resp["result"]


def test_exact_hit_passes_through(server, stub_backend):
    stub_backend.next_eval_response = {
        "kind": "exact", "address": "0x401234", "name": "main",
    }
    r = _call_decompile(server, "0x401234")
    assert r["isError"] is False
    assert r["structuredContent"].get("address_adjusted") is None
    # The backend received the un-adjusted address.
    assert any(
        c[0] == "decomp_function" and c[1][1] == "0x401234"
        for c in stub_backend.calls
    )


def test_mid_function_silent_adjust(server, stub_backend):
    stub_backend.next_eval_response = {
        "kind": "containing", "reason": "mid_function",
        "address": "0x401200", "name": "parse_input",
    }
    r = _call_decompile(server, "0x40123a")
    assert r["isError"] is False
    adj = r["structuredContent"]["address_adjusted"]
    assert adj == {
        "requested": "0x40123a",
        "resolved": "0x401200",
        "reason": "mid_function",
    }
    # Backend got the adjusted address, not the original.
    decompiled_args = [c[1][1] for c in stub_backend.calls if c[0] == "decomp_function"]
    assert decompiled_args == ["0x401200"]


def test_plt_thunk_resolves_to_target(server, stub_backend):
    stub_backend.next_eval_response = {
        "kind": "plt_thunk", "reason": "plt_thunk",
        "address": "0x405abc", "name": "puts", "via": ".plt",
    }
    r = _call_decompile(server, "0x401050")
    adj = r["structuredContent"]["address_adjusted"]
    assert adj["resolved"] == "0x405abc"
    assert adj["via"] == ".plt"
    assert adj["reason"] == "plt_thunk"


def test_miss_unanalyzed_code_returns_structured_error(server, stub_backend):
    stub_backend.next_eval_response = {
        "kind": "miss", "is_code": True, "in_section": ".text",
        "reason": "unanalyzed_code",
    }
    r = _call_decompile(server, "0x401abc")
    assert r["isError"] is True
    sc = r["structuredContent"]
    assert sc["error_code"] == "not_found_address"
    assert sc["is_code"] is True
    assert sc["in_section"] == ".text"
    assert "pyghidra.exec" in sc["next_action"]
    assert "createFunction" in sc["pyghidra_hint"]


def test_miss_data_returns_structured_error(server, stub_backend):
    stub_backend.next_eval_response = {
        "kind": "miss", "is_code": False, "in_section": ".rodata", "reason": "data",
    }
    r = _call_decompile(server, "0x600000")
    sc = r["structuredContent"]
    assert sc["error_code"] == "not_found_address"
    assert sc["is_code"] is False
    assert sc["in_section"] == ".rodata"
    assert "data section" in sc["next_action"]


def test_pyghidra_exec_skips_address_tolerance(server, stub_backend):
    """pyghidra.exec passes its `code` arg verbatim; no address resolution."""
    req = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "pyghidra.exec",
            "arguments": {"code": "result = currentProgram.getName()"},
        },
    }
    resp = json.loads(server.handle_json_line(json.dumps(req)))
    r = resp["result"]
    # No resolver invocation for pyghidra.exec.
    eval_calls = [c for c in stub_backend.calls if c[0] == "eval_code"]
    # Exactly one eval_code call -- the real one from the agent, not the resolver.
    assert len(eval_calls) == 1
    assert "currentProgram.getName" in eval_calls[0][1][0]
