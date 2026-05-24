"""search.functions actually does regex by default (the docs promised it)."""

from __future__ import annotations

import json
from unittest.mock import patch


def _call(server, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "search.functions", "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def _matches_fixture(items):
    return {
        "query": "<set by snippet>", "exact": False, "regex": True,
        "limit": 50, "total": len(items), "count": len(items),
        "items": items,
    }


def test_default_path_runs_regex_in_jvm(server, stub_backend):
    """Default path calls eval_code with a regex snippet; the backend's
    substring-based function_by_name is NOT called."""
    sample = [{"name": "parse_args", "entry_point": "0x401234"},
              {"name": "parse_input", "entry_point": "0x401500"}]
    stub_backend.next_eval_response = _matches_fixture(sample)

    with patch.object(stub_backend, "function_by_name") as legacy:
        r = _call(server, {"name": "^parse_", "limit": 10})

    legacy.assert_not_called()  # we did not fall through to substring search
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["regex"] is True
    assert sc["count"] == 2
    assert {it["name"] for it in sc["items"]} == {"parse_args", "parse_input"}


def test_exact_true_falls_through_to_backend(server, stub_backend):
    """exact=true uses the upstream literal-match path; no regex eval_code call."""
    received = {}

    def fake_fbn(session_id, name, *, exact=False, limit=20):
        received["name"] = name
        received["exact"] = exact
        return {"session_id": session_id, "query": name, "exact": exact,
                "limit": limit, "total": 1, "count": 1, "items": []}

    with patch.object(stub_backend, "function_by_name", side_effect=fake_fbn), \
         patch.object(stub_backend, "eval_code") as eval_code:
        r = _call(server, {"name": "main", "exact": True, "limit": 5})

    eval_code.assert_not_called()  # regex pipeline skipped
    assert received["name"] == "main"
    assert received["exact"] is True
    assert r["isError"] is False


def test_invalid_regex_surfaces_bad_args(server, stub_backend):
    """If the agent passes a malformed regex, the inline re.error is
    converted into a structured bad_args response."""
    stub_backend.next_eval_response = {"_regex_error": "unbalanced parenthesis"}
    r = _call(server, {"name": "(unbalanced", "limit": 5})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "name"
    assert "unbalanced" in sc["error"]


def test_empty_name_rejected(server):
    r = _call(server, {"name": "", "limit": 5})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"


def test_non_positive_limit_rejected(server):
    r = _call(server, {"name": "main", "limit": 0})
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "limit"
