"""Regression tests for the redteam-finding batch (F1, F2, F4, F5, F9, F10, F14)."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from tinyghidramcp import _pyghidra_session
from tinyghidramcp.server import SimpleMcpServer, _BACKEND_TOOL_NAME_MAP


def _call(server, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


# ---------------------- F2: truncation marker on xrefs --------------------

def test_F2_truncation_marker_when_count_equals_limit(server, stub_backend):
    """Upstream returns count == limit -> we add truncated: true."""
    items = [
        {"from": f"0x{i:x}", "to": "0x500000",
         "reference_type": "UNCONDITIONAL_CALL",
         "operand_index": 0, "primary": True, "external": False}
        for i in range(5)
    ]
    def fake(session_id, address=None, **kw):
        return {"session_id": session_id, "count": 5, "items": items}
    with patch.object(stub_backend, "xref_to", side_effect=fake):
        r = _call(server, "xrefs.to", {"address": "0x500000", "limit": 5})
    sc = r["structuredContent"]
    assert sc["truncated"] is True
    assert "limit" in sc["truncation_hint"]


def test_F2_no_truncation_marker_below_limit(server, stub_backend):
    items = [{"from": "0x1", "to": "0x500000",
              "reference_type": "UNCONDITIONAL_CALL",
              "operand_index": 0, "primary": True, "external": False}]
    def fake(session_id, address=None, **kw):
        return {"session_id": session_id, "count": 1, "items": items}
    with patch.object(stub_backend, "xref_to", side_effect=fake):
        r = _call(server, "xrefs.to", {"address": "0x500000", "limit": 100})
    sc = r["structuredContent"]
    assert sc.get("truncated") is not True
    assert "truncation_hint" not in sc


# ---------------------- F4: search.strings regex ---------------------------

def test_F4_search_strings_runs_regex_by_default(server, stub_backend):
    sample = {
        "query": "^flag", "regex": True, "offset": 0, "limit": 100,
        "total": 2, "count": 2,
        "items": [{"address": "0x1", "value": "flag{a}", "length": 7},
                  {"address": "0x2", "value": "flag{b}", "length": 7}],
    }
    stub_backend.next_eval_response = sample
    with patch.object(stub_backend, "binary_strings") as legacy:
        r = _call(server, "search.strings", {"query": "^flag", "limit": 100})
    legacy.assert_not_called()  # never fell through to substring upstream
    sc = r["structuredContent"]
    assert sc["regex"] is True
    assert sc["count"] == 2


def test_F4_search_strings_invalid_regex_bad_args(server, stub_backend):
    stub_backend.next_eval_response = {"_regex_error": "unbalanced parenthesis"}
    r = _call(server, "search.strings", {"query": "(unbal", "limit": 10})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "query"


def test_F4_search_strings_exact_true_falls_through(server, stub_backend):
    received = {}
    def fake_bs(session_id, *, offset=0, limit=100, query=None):
        received["query"] = query
        return {"session_id": session_id, "offset": offset, "limit": limit,
                "total": 0, "count": 0, "items": []}
    with patch.object(stub_backend, "binary_strings", side_effect=fake_bs), \
         patch.object(stub_backend, "eval_code") as eval_code:
        _call(server, "search.strings", {"query": "literal", "exact": True})
    eval_code.assert_not_called()
    assert received["query"] == "literal"


def test_F4_search_strings_empty_query_lists_all(server, stub_backend):
    """No query -> upstream returns the full paginated list (no regex needed)."""
    received = {}
    def fake_bs(session_id, *, offset=0, limit=100, query=None):
        received["query"] = query
        return {"session_id": session_id, "offset": offset, "limit": limit,
                "total": 0, "count": 0, "items": []}
    with patch.object(stub_backend, "binary_strings", side_effect=fake_bs):
        _call(server, "search.strings", {})
    assert received["query"] is None


# ---------------------- F5: sys.exit interception --------------------------

class _ExitBackend:
    def __init__(self): self.calls = 0
    def eval_code(self, code, *, session_id=None):
        self.calls += 1
        raise SystemExit(99)
    def __getattr__(self, name):
        if name in _BACKEND_TOOL_NAME_MAP:
            return lambda *a, **kw: {"ok": True}
        raise AttributeError(name)


@pytest.fixture
def exit_server():
    srv = SimpleMcpServer(_ExitBackend())
    srv._auto_session_id = "sess-fake"
    yield srv
    _pyghidra_session.reset()


def test_F5_sys_exit_is_intercepted_not_propagated(exit_server):
    r = _call(exit_server, "pyghidra.exec", {"code": "import sys; sys.exit(0)"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "unsupported"
    assert "sys.exit" in sc["error"]


# ---------------------- F9: degenerate function body -----------------------

def test_F9_degenerate_body_skips_expansion(server, stub_backend):
    """If body_min == body_max, do not auto-expand; pass address through."""
    # First eval: address-tolerance resolver, returns exact hit.
    # Second eval: body lookup, returns (X, X) -- degenerate.
    responses = [
        {"kind": "exact", "address": "0x401234", "name": "thunk"},
        ("0x401234", "0x401234"),  # degenerate
    ]
    def fake_eval(code, *, session_id=None):
        return {"result": responses.pop(0)}
    received = {}
    def fake_xref_from(session_id, address=None, start=None, end=None, limit=100):
        received["address"] = address
        received["start"] = start
        received["end"] = end
        return {"session_id": session_id, "count": 0, "items": []}
    with patch.object(stub_backend, "eval_code", side_effect=fake_eval), \
         patch.object(stub_backend, "xref_from", side_effect=fake_xref_from):
        r = _call(server, "xrefs.from", {"address": "0x401234"})
    # Original address passed through; no start/end substitution.
    assert received["address"] == "0x401234"
    assert received["start"] is None
    assert received["end"] is None
    assert "address_expanded" not in r["structuredContent"]


# ---------------------- F10: callgraph tolerance ---------------------------

def test_F10_callgraph_accepts_symbol_names(server, stub_backend):
    """source_function / target_function go through address tolerance now."""
    responses = [
        # resolver for source_function="entry"
        {"kind": "exact", "reason": "symbol_lookup",
         "address": "0x104860", "name": "_start"},
        # resolver for target_function="main"
        {"kind": "exact", "reason": "symbol_lookup",
         "address": "0x401234", "name": "main"},
    ]
    def fake_eval(code, *, session_id=None):
        return {"result": responses.pop(0)}
    received = {}
    def fake_cg(session_id, source_function=None, target_function=None,
                max_depth=4, limit=20):
        received["source"] = source_function
        received["target"] = target_function
        return {"session_id": session_id, "count": 0, "items": []}
    with patch.object(stub_backend, "eval_code", side_effect=fake_eval), \
         patch.object(stub_backend, "callgraph_paths", side_effect=fake_cg):
        r = _call(server, "callgraph",
                  {"source_function": "entry", "target_function": "main"})
    # Names resolved to addresses before backend was called.
    assert received["source"] == "0x104860"
    assert received["target"] == "0x401234"
    assert r["isError"] is False


# ---------------------- F14: busy-executor fast-fail -----------------------

class _SlowBackend:
    def __init__(self): self.sleep_seconds = 0.0
    def eval_code(self, code, *, session_id=None):
        time.sleep(self.sleep_seconds)
        return {"result": None, "mode_transitioned": False, "transitioned_session_ids": []}
    def __getattr__(self, name):
        if name in _BACKEND_TOOL_NAME_MAP:
            return lambda *a, **kw: {"ok": True}
        raise AttributeError(name)


@pytest.fixture
def slow_server():
    srv = SimpleMcpServer(_SlowBackend())
    srv._auto_session_id = "sess-fake"
    yield srv
    _pyghidra_session.reset()


def test_F14_busy_executor_fast_fails_next_call(slow_server):
    # 1) First call times out; the worker keeps sleeping.
    slow_server._backend.sleep_seconds = 3
    r1 = _call(slow_server, "pyghidra.exec",
               {"code": "1 + 1", "timeout_sec": 0.2})
    assert r1["isError"] is True
    assert r1["structuredContent"]["error_code"] == "timeout"

    # 2) Second call should NOT wait its full timeout for the abandoned
    #    worker. It should fail fast with error_code=state.
    t0 = time.monotonic()
    r2 = _call(slow_server, "pyghidra.exec",
               {"code": "1 + 1", "timeout_sec": 5})
    elapsed = time.monotonic() - t0
    sc2 = r2["structuredContent"]
    assert r2["isError"] is True
    assert sc2["error_code"] == "state"
    assert "still running" in sc2["error"]
    assert elapsed < 1.0, f"fast-fail took {elapsed:.2f}s; should be near-instant"
