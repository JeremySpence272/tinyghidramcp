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
# Validation now lives in backend.disasm_function (matching xref_to, etc.).
# The conftest stub mirrors that. No custom server wrapper.

def test_bug2_disassemble_rejects_negative_limit(server, stub_backend):
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    r = _call(server, "disassemble", {"address": "0x401234", "limit": -1})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert "limit must be > 0" in sc["error"]


def test_bug2_disassemble_rejects_zero_limit(server, stub_backend):
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    r = _call(server, "disassemble", {"address": "0x401234", "limit": 0})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert "limit must be > 0" in sc["error"]


def test_bug2_disassemble_accepts_positive_limit(server, stub_backend):
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
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


# ---------------------- Bug 4: resolve rejects out-of-image -----------------
# Validation now lives in backend.address_resolve. Matches decompile's
# behavior: any address-shaped query outside the loaded image is rejected
# instead of returning a synthetic DAT_* label.

def test_bug4_resolve_rejects_out_of_image_address(server, stub_backend):
    def fake_resolve(session_id, query):
        # Mirror the real backend's check.
        from tinyghidramcp.backend import GhidraBackendError
        if isinstance(query, str) and query.startswith("0x"):
            n = int(query, 16)
            if n < 0x100000 or n > 0x200000:
                raise GhidraBackendError(
                    f"address {query!r} falls outside the loaded image"
                )
        return {"session_id": session_id, "query": query, "resolved": True}
    with patch.object(stub_backend, "address_resolve", side_effect=fake_resolve):
        r = _call(server, "resolve", {"query": "0x0"})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert "outside the loaded image" in sc["error"]


def test_bug4_resolve_accepts_in_image_address(server, stub_backend):
    def fake_resolve(session_id, query):
        return {"session_id": session_id, "query": query, "resolved": True,
                "address": query, "symbols": [], "functions": []}
    with patch.object(stub_backend, "address_resolve", side_effect=fake_resolve):
        r = _call(server, "resolve", {"query": "0x104860"})
    assert r["isError"] is False
    assert r["structuredContent"]["resolved"] is True


def test_bug4_resolve_accepts_name_query(server, stub_backend):
    """Names go through the symbol-table path and aren't subject to the
    in-image check (which only applies to address-shaped queries)."""
    def fake_resolve(session_id, query):
        return {"session_id": session_id, "query": query, "resolved": True,
                "symbols": [{"name": "main", "address": "00104860"}],
                "functions": []}
    with patch.object(stub_backend, "address_resolve", side_effect=fake_resolve):
        r = _call(server, "resolve", {"query": "main"})
    assert r["isError"] is False


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
