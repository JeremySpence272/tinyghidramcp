"""max_lines / max_lines_each enforcement on decompile and decompile.batch."""

from __future__ import annotations

import json

from tinyghidramcp.server import DECOMPILE_HARD_CEILING_LINES, _apply_max_lines


LONG_DECOMPILE = "\n".join(f"line {i};" for i in range(2000))


def test_apply_max_lines_truncates():
    payload = {"decompiled": LONG_DECOMPILE}
    out = _apply_max_lines(payload, 100)
    assert out["decompiled"].count("\n") == 99
    assert out["truncated_lines"] == 1900
    assert out["max_lines_applied"] == 100


def test_apply_max_lines_default_when_none():
    payload = {"decompiled": LONG_DECOMPILE}
    out = _apply_max_lines(payload, None)
    # Default ceiling is 800
    assert out["max_lines_applied"] == 800


def test_apply_max_lines_hard_ceiling():
    """Even if max_lines is huge, the hard ceiling clips it."""
    huge = "\n".join(f"line {i};" for i in range(DECOMPILE_HARD_CEILING_LINES + 100))
    payload = {"decompiled": huge}
    out = _apply_max_lines(payload, 999999)
    assert out["max_lines_applied"] == DECOMPILE_HARD_CEILING_LINES


def test_apply_max_lines_no_change_when_short():
    short = "one\ntwo\nthree"
    payload = {"decompiled": short}
    out = _apply_max_lines(payload, 100)
    assert out["decompiled"] == short
    assert "truncated_lines" not in out


def _call(server, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_decompile_max_lines_wired_through(server, stub_backend):
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    stub_backend.decomp_function = lambda session_id, function_start, *, timeout_secs=30: {
        "decompiled": LONG_DECOMPILE,
        "function_name": "main",
    }
    r = _call(server, "decompile", {"function_start": "0x401234", "max_lines": 50})
    sc = r["structuredContent"]
    assert sc["max_lines_applied"] == 50
    assert sc["decompiled"].count("\n") == 49


def test_decompile_max_lines_rejects_bad_arg(server):
    r = _call(server, "decompile", {"function_start": "0x401234", "max_lines": "lots"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "max_lines"


def test_decompile_max_lines_appears_in_schema(server):
    res = server._dispatch_tools_list({})
    decompile_spec = next(t for t in res["tools"] if t["name"] == "decompile")
    assert "max_lines" in decompile_spec["inputSchema"]["properties"]
