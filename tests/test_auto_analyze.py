"""Step-4 auto-analysis: 10s wall cap, success path, retry-after-success."""

from __future__ import annotations

import json
import time

import pytest

from tinyghidramcp import address_tolerance


@pytest.fixture
def shorter_cap(monkeypatch):
    """Reduce the wall cap so timeout tests run quickly."""
    monkeypatch.setattr(address_tolerance, "AUTO_ANALYZE_WALL_SEC", 1)


def _call_decompile(server, addr):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "decompile", "arguments": {"target": addr}}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_auto_analyze_succeeds_on_second_pass(server, stub_backend):
    """First eval returns unanalyzed_code; second returns a function -> exact hit."""
    responses = [
        {"kind": "miss", "is_code": True, "in_section": ".text", "reason": "unanalyzed_code"},
        {"kind": "exact", "reason": "auto_analyzed", "address": "0x401abc", "name": "FUN_401abc"},
    ]

    def fake_eval(code, *, session_id=None):
        return {"result": responses.pop(0)}

    stub_backend.eval_code = fake_eval
    r = _call_decompile(server, "0x401abc")
    assert r["isError"] is False
    sc = r["structuredContent"]
    # The address was auto-adjusted (resolved differs from requested? No -- both 0x401abc).
    # Since they match here, address_adjusted is None. The decompile_of arg confirms backend got the addr.
    assert sc["decompile_of"] == "0x401abc"


def test_auto_analyze_failure_returns_unanalyzed_code_miss(server, stub_backend):
    """Both passes return unanalyzed_code -> structured miss with reason."""
    responses = [
        {"kind": "miss", "is_code": True, "in_section": ".text", "reason": "unanalyzed_code"},
        {"kind": "miss", "is_code": True, "in_section": None, "reason": "unanalyzed_code"},
    ]

    def fake_eval(code, *, session_id=None):
        return {"result": responses.pop(0)}

    stub_backend.eval_code = fake_eval
    r = _call_decompile(server, "0x401abc")
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "not_found_address"
    assert "createFunction" in sc["pyghidra_hint"]


def test_auto_analyze_wall_cap_triggers_state_error(server, stub_backend, shorter_cap):
    """If the second pass blocks past the wall cap, surface state error."""
    call_count = [0]

    def fake_eval(code, *, session_id=None):
        call_count[0] += 1
        if call_count[0] == 1:
            # First pass: trigger step 4
            return {"result": {"kind": "miss", "is_code": True,
                               "in_section": ".text", "reason": "unanalyzed_code"}}
        # Second pass: simulate slow analysis
        time.sleep(3)
        return {"result": {"kind": "exact", "reason": "auto_analyzed",
                           "address": "0x401abc", "name": "FUN_401abc"}}

    stub_backend.eval_code = fake_eval
    r = _call_decompile(server, "0x401abc")
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "state"
    assert "wall cap" in sc["error"]
    assert "createFunction" in sc["pyghidra_hint"]
