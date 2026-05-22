"""decompile.batch handler: iterates targets, returns dict keyed by input."""

from __future__ import annotations

import json
from unittest.mock import patch


def _call_batch(server, targets, **kwargs):
    args = {"targets": targets}
    args.update(kwargs)
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "decompile.batch", "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_batch_rejects_empty_targets(server):
    r = _call_batch(server, [])
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "targets"


def test_batch_rejects_non_int_max_lines(server):
    r = _call_batch(server, ["main"], max_lines_each="lots")
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "max_lines_each"


def test_batch_iterates_and_keys_by_input(server, stub_backend):
    """Each target is resolved independently; result dict is keyed by input string."""
    resolver_responses = [
        {"kind": "exact", "address": "0x401234", "name": "main"},
        {"kind": "exact", "reason": "symbol_lookup",
         "address": "0x405000", "name": "parse_args"},
    ]

    def fake_eval(code, *, session_id=None):
        return {"result": resolver_responses.pop(0)}

    with patch.object(stub_backend, "eval_code", side_effect=fake_eval):
        r = _call_batch(server, ["0x401234", "parse_args"])

    sc = r["structuredContent"]
    assert sc["count"] == 2
    assert set(sc["results"].keys()) == {"0x401234", "parse_args"}
    # the second entry should carry address_adjusted because we passed a name
    parse_args_entry = sc["results"]["parse_args"]
    assert parse_args_entry["address_adjusted"]["resolved"] == "0x405000"


def test_batch_records_per_target_errors_without_failing_whole_call(server, stub_backend):
    """One target's miss doesn't take down the others."""
    resolver_responses = [
        {"kind": "exact", "address": "0x401234", "name": "main"},
        {"kind": "miss", "reason": "name_not_found", "is_code": False, "in_section": None,
         "name": "ghost"},
    ]

    def fake_eval(code, *, session_id=None):
        return {"result": resolver_responses.pop(0)}

    with patch.object(stub_backend, "eval_code", side_effect=fake_eval):
        r = _call_batch(server, ["main", "ghost"])

    sc = r["structuredContent"]
    assert r["isError"] is False  # whole call succeeds
    assert sc["count"] == 2
    assert "decompile_of" in sc["results"]["main"]
    assert sc["results"]["ghost"]["error_code"] == "not_found_name"
