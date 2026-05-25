"""Regression tests for the second redteam batch."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest


def _call(server, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


# ---------------------- Bug 2: disassemble negative limit ------------------

def test_bug2_disassemble_rejects_negative_limit(server, stub_backend):
    r = _call(server, "disassemble", {"address": "0x401234", "limit": -1})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "limit"


def test_bug2_disassemble_rejects_zero_limit(server, stub_backend):
    r = _call(server, "disassemble", {"address": "0x401234", "limit": 0})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"


def test_bug2_disassemble_accepts_positive_limit(server, stub_backend):
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    def fake_disasm(session_id, address, *, limit=None):
        return {"session_id": session_id, "address": address, "limit": limit,
                "count": 0, "items": []}
    with patch.object(stub_backend, "disasm_function", side_effect=fake_disasm):
        r = _call(server, "disassemble", {"address": "0x401234", "limit": 10})
    assert r["isError"] is False


# ---------------------- Bug 3: search.functions empty pattern --------------

def test_bug3_search_functions_empty_name_lists_all(server, stub_backend):
    """Empty `name` should NOT reject; should iterate via the regex path
    with a match-anything pattern."""
    stub_backend.next_eval_response = {
        "query": ".*", "exact": False, "regex": True,
        "limit": 50, "total": 3, "count": 3,
        "items": [
            {"name": "a"}, {"name": "b"}, {"name": "c"},
        ],
    }
    r = _call(server, "search.functions", {"name": "", "limit": 50})
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["count"] == 3


def test_bug3_search_functions_missing_name_lists_all(server, stub_backend):
    stub_backend.next_eval_response = {
        "query": ".*", "regex": True, "total": 0, "count": 0, "items": [],
        "limit": 50, "exact": False,
    }
    r = _call(server, "search.functions", {"limit": 50})
    assert r["isError"] is False


# ---------------------- Bug 4: resolve in_image flag ----------------------

def test_bug4_resolve_address_in_image(server, stub_backend):
    """Address inside the loaded range -> in_image: true."""
    # Two eval_code calls: image bounds + resolve.
    # We patch eval_code to return only the bounds; backend's address_resolve
    # is the stub default.
    def fake_eval(code, *, session_id=None):
        return {"result": (0x100000, 0x200000)}
    with patch.object(stub_backend, "eval_code", side_effect=fake_eval):
        r = _call(server, "resolve", {"query": "0x150000"})
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["in_image"] is True


def test_bug4_resolve_address_out_of_image(server, stub_backend):
    def fake_eval(code, *, session_id=None):
        return {"result": (0x100000, 0x200000)}
    with patch.object(stub_backend, "eval_code", side_effect=fake_eval):
        r = _call(server, "resolve", {"query": "0x0"})
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["in_image"] is False
    assert "auto-labels" in sc["in_image_hint"]


def test_bug4_resolve_name_query_marks_in_image_unknown(server, stub_backend):
    """Names aren't address-shaped; in_image should be None (unknown)."""
    r = _call(server, "resolve", {"query": "main"})
    sc = r["structuredContent"]
    assert sc["in_image"] is None


# ---------------------- Bug 5: inverted range -----------------------------

def test_bug5_xrefs_from_inverted_range_bad_args(server, stub_backend):
    r = _call(server, "xrefs.from", {"start": "0x1000", "end": "0x500"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "end"


def test_bug5_xrefs_to_inverted_range_bad_args(server, stub_backend):
    r = _call(server, "xrefs.to", {"start": "0xffff", "end": "0x0"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"


def test_bug5_equal_endpoints_allowed(server, stub_backend):
    def fake_xref_from(session_id, address=None, start=None, end=None, limit=100):
        return {"session_id": session_id, "count": 0, "items": []}
    with patch.object(stub_backend, "xref_from", side_effect=fake_xref_from):
        r = _call(server, "xrefs.from", {"start": "0x1000", "end": "0x1000"})
    assert r["isError"] is False


# ---------------------- Bug 8: offset_out_of_range marker -----------------

def test_bug8_offset_out_of_range_attached_on_substring_path(server, stub_backend):
    def fake_bs(session_id, *, offset=0, limit=100, query=None):
        return {"session_id": session_id, "offset": offset, "limit": limit,
                "total": 3, "count": 0, "items": []}
    with patch.object(stub_backend, "binary_strings", side_effect=fake_bs):
        r = _call(server, "search.strings",
                  {"query": "x", "exact": True, "limit": 5, "offset": 100})
    sc = r["structuredContent"]
    assert sc["offset_out_of_range"] is True
    assert "past total=3" in sc["offset_hint"]


def test_bug8_no_marker_when_offset_in_range(server, stub_backend):
    def fake_bs(session_id, *, offset=0, limit=100, query=None):
        return {"session_id": session_id, "offset": offset, "limit": limit,
                "total": 100, "count": 5, "items": [{"v": i} for i in range(5)]}
    with patch.object(stub_backend, "binary_strings", side_effect=fake_bs):
        r = _call(server, "search.strings",
                  {"query": "x", "exact": True, "limit": 5, "offset": 10})
    sc = r["structuredContent"]
    assert "offset_out_of_range" not in sc


def test_bug8_marker_on_regex_path(server, stub_backend):
    stub_backend.next_eval_response = {
        "query": "x", "regex": True, "offset": 100, "limit": 5,
        "total": 3, "count": 0, "items": [],
    }
    r = _call(server, "search.strings", {"query": "x", "limit": 5, "offset": 100})
    sc = r["structuredContent"]
    assert sc["offset_out_of_range"] is True
