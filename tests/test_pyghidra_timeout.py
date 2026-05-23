"""pyghidra.exec wall-clock timeout: budget enforcement + rollback to last-good."""

from __future__ import annotations

import json
import time
import types

import pytest

from tinyghidramcp import _pyghidra_session
from tinyghidramcp.server import SimpleMcpServer, _BACKEND_TOOL_NAME_MAP


@pytest.fixture(autouse=True)
def _reset_session_state():
    _pyghidra_session.reset()
    yield
    _pyghidra_session.reset()


class _SlowBackend:
    """Stub backend whose eval_code blocks for a configurable duration."""

    def __init__(self):
        self.sleep_seconds = 0.0
        self.calls = 0

    def eval_code(self, code, *, session_id=None):
        self.calls += 1
        time.sleep(self.sleep_seconds)
        # Pretend the script ran and emit upstream's success shape.
        return {"result": None, "mode_transitioned": False, "transitioned_session_ids": []}

    def __getattr__(self, name):
        if name in _BACKEND_TOOL_NAME_MAP:
            return lambda *a, **kw: {"ok": True}
        raise AttributeError(name)


@pytest.fixture
def slow_server():
    srv = SimpleMcpServer(_SlowBackend())
    srv._auto_session_id = "sess-fake"
    return srv


def _call(server, code, timeout_sec=None):
    args = {"code": code}
    if timeout_sec is not None:
        args["timeout_sec"] = timeout_sec
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "pyghidra.exec", "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_timeout_triggers_timeout_error_code(slow_server):
    slow_server._backend.sleep_seconds = 3
    r = _call(slow_server, "1 + 1", timeout_sec=0.2)
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "timeout"
    assert "exceeded" in sc["error"]
    assert "write the script to disk" in sc["next_action"]


def test_timeout_rolls_back_globals(slow_server):
    # Seed the persistent globals so we have a "last-good" state to assert.
    _pyghidra_session.STATE["sticky"] = "before"

    slow_server._backend.sleep_seconds = 3
    r = _call(slow_server, "x = 1", timeout_sec=0.2)
    assert r["isError"] is True
    # After the timed-out call, STATE must look exactly like the pre-call snapshot.
    assert _pyghidra_session.STATE == {"sticky": "before"}


def test_timeout_resets_invalidate_flag(slow_server):
    _pyghidra_session.STATE["seed"] = 1
    _pyghidra_session.INVALIDATE_REQUESTED = True

    slow_server._backend.sleep_seconds = 3
    r = _call(slow_server, "1 + 1", timeout_sec=0.2)
    assert r["isError"] is True
    # The invalidate flag pre-call was True; restore should bring it back.
    assert _pyghidra_session.INVALIDATE_REQUESTED is True


def test_within_budget_passes_through(slow_server):
    slow_server._backend.sleep_seconds = 0.05
    r = _call(slow_server, "1 + 1", timeout_sec=2)
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["duration_ms"] >= 50


def test_default_timeout_is_60_seconds(slow_server):
    """Schema and constant: default budget is 60s when no timeout_sec is given."""
    # Just confirm the constant; we don't actually sleep 60s in a test.
    assert SimpleMcpServer.PYGHIDRA_EXEC_DEFAULT_TIMEOUT_SEC == 60


def test_timeout_sec_caps_at_max(slow_server):
    """Even a huge timeout_sec is silently capped."""
    slow_server._backend.sleep_seconds = 0.05
    r = _call(slow_server, "1", timeout_sec=99999)
    assert r["isError"] is False  # works fine; cap doesn't reject, just clamps


def test_timeout_sec_rejects_non_positive(slow_server):
    r = _call(slow_server, "1", timeout_sec=0)
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "timeout_sec"


def test_timeout_sec_appears_in_schema(slow_server):
    res = slow_server._dispatch_tools_list({})
    spec = next(t for t in res["tools"] if t["name"] == "pyghidra.exec")
    assert "timeout_sec" in spec["inputSchema"]["properties"]
