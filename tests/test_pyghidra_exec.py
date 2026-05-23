"""pyghidra.exec wrapper: bound aliases, persistent globals, cache helper."""

from __future__ import annotations

import json
import types

import pytest

from tinyghidramcp import _pyghidra_session
from tinyghidramcp.server import SimpleMcpServer, _BACKEND_TOOL_NAME_MAP


@pytest.fixture(autouse=True)
def _reset_session_state():
    """Each test starts with empty pyghidra session globals."""
    _pyghidra_session.reset()
    yield
    _pyghidra_session.reset()


class FakeProgram:
    def __init__(self, name: str = "binary"):
        self._name = name
        self.functionManager = object()
        self.symbolTable = object()
        self.memory = object()
        self.listing = object()

    def getFunctionManager(self):
        return self.functionManager

    def getSymbolTable(self):
        return self.symbolTable

    def getMemory(self):
        return self.memory

    def getListing(self):
        return self.listing

    def getName(self):
        return self._name


class _EvalCodeBackend:
    """Backend stub that actually executes the wrapped code via Python exec()."""

    def __init__(self, program=None, flat_api=None, decompiler=None):
        self._program = program or FakeProgram()
        self._flat_api = flat_api
        self._decompiler = decompiler
        self.last_code = None
        self.last_context_snapshot = None

    def eval_code(self, code, *, session_id=None):
        # Mirror the upstream eval_code shape, but execute the code so the
        # server's prelude/postlude run against real Python semantics.
        import io
        from contextlib import redirect_stdout, redirect_stderr

        context = {
            "program": self._program,
            "flat_api": self._flat_api,
            "decompiler": self._decompiler,
            "listing": self._program.getListing(),
            "memory": self._program.getMemory(),
            "symbol_table": self._program.getSymbolTable(),
            "session_id": session_id,
        }
        self.last_code = code

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                compiled = compile(code, "<test>", "eval")
                result = eval(compiled, context, context)
            except SyntaxError:
                compiled = compile(code, "<test>", "exec")
                exec(compiled, context, context)
                result = context.get("_")
        self.last_context_snapshot = context
        payload = {"result": result, "mode_transitioned": False, "transitioned_session_ids": []}
        if stdout.getvalue():
            payload["stdout"] = stdout.getvalue()
        if stderr.getvalue():
            payload["stderr"] = stderr.getvalue()
        return payload

    # Map every other tool method to a no-op stub
    def __getattr__(self, name):
        if name in _BACKEND_TOOL_NAME_MAP:
            return lambda *a, **kw: {"ok": True}
        raise AttributeError(name)


@pytest.fixture
def eval_server():
    srv = SimpleMcpServer(_EvalCodeBackend())
    srv._auto_session_id = "sess-fake"
    return srv


def _call(server, code):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "pyghidra.exec", "arguments": {"code": code}}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_expression_returns_value(eval_server):
    r = _call(eval_server, "currentProgram.getName()")
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["result"] == "binary"


def test_aliases_bound_in_namespace(eval_server):
    r = _call(eval_server, "[currentProgram is not None, fm is not None, sm is not None, mem is not None, cache is not None]")
    sc = r["structuredContent"]
    assert sc["result"] == [True, True, True, True, True]


def test_globals_persist_across_calls(eval_server):
    _call(eval_server, "x = 42")
    r = _call(eval_server, "x + 1")
    assert r["structuredContent"]["result"] == 43


def test_result_does_not_persist_across_calls(eval_server):
    """Regression: a previous call's `result = ...` must NOT clobber the
    next call's expression value. The postlude's `if 'result' in globals():
    _ = result` rule would otherwise use the stale value injected from STATE.
    Excluding `result` and `_` from persistence is the fix."""
    # Script call sets `result` explicitly.
    r1 = _call(eval_server, "result = 'from-call-1'")
    assert r1["structuredContent"]["result"] == "from-call-1"

    # Pure-expression call. With the bug, this would still return
    # 'from-call-1' because the postlude re-runs `_ = result`. With the
    # fix, `result` is not in STATE, so the expression's value wins.
    r2 = _call(eval_server, "currentProgram.getName()")
    assert r2["structuredContent"]["result"] == "binary"


def test_script_result_variable_is_returned(eval_server):
    r = _call(eval_server, "x = 5\ny = 7\nresult = x * y")
    assert r["structuredContent"]["result"] == 35


def test_cache_invalidate_sets_flag(eval_server):
    r = _call(eval_server, "cache.invalidate()")
    sc = r["structuredContent"]
    assert sc["cache_invalidate_requested"] is True
    # Flag is cleared after read; next call should report False.
    r2 = _call(eval_server, "1")
    assert r2["structuredContent"]["cache_invalidate_requested"] is False


def test_globals_size_bytes_reported(eval_server):
    _call(eval_server, "big = 'x' * 4096")
    r = _call(eval_server, "1")
    assert r["structuredContent"]["globals_size_bytes"] > 1000


def test_stdout_captured(eval_server):
    r = _call(eval_server, "print('hello from agent')")
    assert "hello from agent" in r["structuredContent"]["stdout"]


def test_empty_code_rejected(eval_server):
    r = _call(eval_server, "")
    sc = r["structuredContent"]
    assert r["isError"] is True
    assert sc["error_code"] == "bad_args"
    assert sc["field"] == "code"
