"""xrefs.to / xrefs.from: include_data flag toggles filtering of data refs."""

from __future__ import annotations

import json

import pytest


CODE_REF = {
    "from": "0x401234", "to": "0x405000",
    "reference_type": "UNCONDITIONAL_CALL",
    "operand_index": 0, "primary": True, "external": False,
}
DATA_REF_READ = {
    "from": "0x401234", "to": "0x405000",
    "reference_type": "READ",
    "operand_index": 1, "primary": True, "external": False,
}
DATA_REF_DATA = {
    "from": "0x401234", "to": "0x405000",
    "reference_type": "DATA",
    "operand_index": 1, "primary": True, "external": False,
}


def _call(server, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def _wire_xrefs(stub_backend, items):
    """Wire xref_to / xref_from to return the given items list."""
    def fake_xref(session_id, address=None, **kw):
        return {"session_id": session_id, "address": address,
                "count": len(items), "items": items}
    stub_backend.xref_to = fake_xref
    stub_backend.xref_from = fake_xref


@pytest.mark.parametrize("tool", ["xrefs.to", "xrefs.from"])
def test_default_drops_data_references(server, stub_backend, tool):
    _wire_xrefs(stub_backend, [CODE_REF, DATA_REF_READ, DATA_REF_DATA])
    r = _call(server, tool, {"address": "0x405000"})
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["count"] == 1
    assert sc["items"][0]["reference_type"] == "UNCONDITIONAL_CALL"
    assert sc["filtered_out"] == {"count": 2, "reason": "data refs (include_data=false)"}


@pytest.mark.parametrize("tool", ["xrefs.to", "xrefs.from"])
def test_no_filtered_out_marker_when_nothing_to_filter(server, stub_backend, tool):
    """When the upstream returned only code refs (or zero refs), the
    `filtered_out` marker is absent — otherwise the agent might wrongly
    assume that include_data=true would surface more."""
    _wire_xrefs(stub_backend, [CODE_REF])  # only a code ref; nothing to filter
    r = _call(server, tool, {"address": "0x405000"})
    sc = r["structuredContent"]
    assert sc["count"] == 1
    assert "filtered_out" not in sc


@pytest.mark.parametrize("tool", ["xrefs.to", "xrefs.from"])
def test_include_data_true_keeps_everything(server, stub_backend, tool):
    _wire_xrefs(stub_backend, [CODE_REF, DATA_REF_READ, DATA_REF_DATA])
    r = _call(server, tool, {"address": "0x405000", "include_data": True})
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["count"] == 3
    assert "filtered_out" not in sc


def test_include_data_appears_in_schema(server):
    res = server._dispatch_tools_list({})
    for name in ("xrefs.to", "xrefs.from"):
        spec = next(t for t in res["tools"] if t["name"] == name)
        assert "include_data" in spec["inputSchema"]["properties"], (
            f"{name} schema missing include_data"
        )
