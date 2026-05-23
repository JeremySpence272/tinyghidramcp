"""xrefs.from auto-expands a function-entry address to the body range."""

from __future__ import annotations

import json
from unittest.mock import patch


CODE_REF_AT_OFFSET = {
    "from": "0x104872", "to": "0x127a5f",
    "reference_type": "UNCONDITIONAL_CALL",
    "operand_index": 0, "primary": True, "external": False,
}


def _call(server, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "xrefs.from", "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_xrefs_from_function_entry_auto_expands_to_body(server, stub_backend):
    """When `address` resolves to a function entry, the handler swaps to a
    body-spanning start/end range so the agent sees refs from the whole
    function, not just from the entry instruction."""
    # First eval_code call is the address-tolerance resolver, second is the
    # body-lookup snippet our handler uses to find body_min / body_max.
    resolver_responses = [
        # 1) resolver: function entry exact-hit
        {"kind": "exact", "address": "0x104860", "name": "_start"},
        # 2) _lookup_function_body: returns (body_min, body_max)
        ("0x104860", "0x104885"),
    ]

    def fake_eval(code, *, session_id=None):
        return {"result": resolver_responses.pop(0)}

    received_args = {}

    def fake_xref_from(session_id, address=None, start=None, end=None, limit=100):
        received_args["address"] = address
        received_args["start"] = start
        received_args["end"] = end
        return {"session_id": session_id, "count": 1, "items": [CODE_REF_AT_OFFSET]}

    with patch.object(stub_backend, "eval_code", side_effect=fake_eval), \
         patch.object(stub_backend, "xref_from", side_effect=fake_xref_from):
        r = _call(server, {"address": "0x104860", "limit": 20})

    sc = r["structuredContent"]
    assert r["isError"] is False
    # Auto-expansion swapped `address` for start/end
    assert received_args["address"] is None
    assert received_args["start"] == "0x104860"
    assert received_args["end"] == "0x104885"
    # Response advertises the expansion
    assert sc["address_expanded"] == {
        "requested": "0x104860",
        "start": "0x104860",
        "end": "0x104885",
        "reason": "function_body",
    }


def test_xrefs_from_passthrough_when_address_is_not_a_function(server, stub_backend):
    """If the address resolves to data or a miss, no expansion fires."""
    resolver_responses = [
        # resolver: miss (data section)
        {"kind": "miss", "reason": "data", "is_code": False, "in_section": ".rodata"},
    ]

    def fake_eval(code, *, session_id=None):
        return {"result": resolver_responses.pop(0)}

    received_args = {}

    def fake_xref_from(session_id, address=None, start=None, end=None, limit=100):
        received_args["address"] = address
        received_args["start"] = start
        received_args["end"] = end
        return {"session_id": session_id, "count": 0, "items": []}

    with patch.object(stub_backend, "eval_code", side_effect=fake_eval), \
         patch.object(stub_backend, "xref_from", side_effect=fake_xref_from):
        r = _call(server, {"address": "0x403000"})

    sc = r["structuredContent"]
    # No expansion: address passes through unchanged.
    assert received_args["address"] == "0x403000"
    assert received_args["start"] is None
    assert received_args["end"] is None
    assert "address_expanded" not in sc


def test_xrefs_from_does_not_expand_when_start_end_already_supplied(server, stub_backend):
    """If the caller already provided start/end, leave them alone."""
    received_args = {}

    def fake_xref_from(session_id, address=None, start=None, end=None, limit=100):
        received_args["start"] = start
        received_args["end"] = end
        return {"session_id": session_id, "count": 0, "items": []}

    with patch.object(stub_backend, "xref_from", side_effect=fake_xref_from):
        r = _call(server, {"start": "0x400000", "end": "0x500000"})

    assert r["isError"] is False
    assert received_args["start"] == "0x400000"
    assert received_args["end"] == "0x500000"


def test_xrefs_to_does_NOT_auto_expand(server, stub_backend):
    """Only xrefs.from auto-expands. xrefs.to of a function entry is
    semantically correct (who calls X) and must not be rewritten."""
    received_args = {}

    def fake_xref_to(session_id, address=None, start=None, end=None, limit=100):
        received_args["address"] = address
        return {"session_id": session_id, "count": 0, "items": []}

    with patch.object(stub_backend, "xref_to", side_effect=fake_xref_to):
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "xrefs.to",
                          "arguments": {"address": "0x104860"}}}
        r = json.loads(server.handle_json_line(json.dumps(req)))["result"]

    assert received_args["address"] == "0x104860"
    assert "address_expanded" not in r["structuredContent"]
