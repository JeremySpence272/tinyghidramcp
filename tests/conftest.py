"""Shared test fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _disable_telemetry(monkeypatch):
    """Disable telemetry by default for unit tests; override per-test as needed."""
    monkeypatch.setenv("TINYGHIDRAMCP_TELEMETRY_DIR", "")
    yield


@pytest.fixture
def telemetry_dir(tmp_path, monkeypatch):
    """Enable telemetry into a per-test directory."""
    d = tmp_path / "telemetry"
    d.mkdir()
    monkeypatch.setenv("TINYGHIDRAMCP_TELEMETRY_DIR", str(d))
    monkeypatch.setenv("TINYGHIDRAMCP_SESSION_ID", "test-session")
    yield d


@pytest.fixture
def stub_backend():
    """Backend stub that returns canned responses for any mapped method.

    Tests set ``backend.next_eval_response`` before calling a tool that triggers
    the address-tolerance pipeline. Each stub method records its last call in
    ``backend.calls``.
    """
    from tinyghidramcp.server import _BACKEND_TOOL_NAME_MAP

    class StubBackend:
        def __init__(self):
            self.next_eval_response = None
            self.calls: list[tuple[str, tuple, dict]] = []

        def _record(self, name, args, kwargs):
            self.calls.append((name, args, kwargs))

        def eval_code(self, code, *, session_id=None):
            self._record("eval_code", (code,), {"session_id": session_id})
            return {"result": self.next_eval_response}

        def decomp_function(self, session_id, function_start, *, timeout_secs=30):
            self._record("decomp_function", (session_id, function_start),
                         {"timeout_secs": timeout_secs})
            return {"ok": True, "decompile_of": function_start}

        def disasm_function(self, session_id, address, *, limit=None):
            self._record("disasm_function", (session_id, address), {"limit": limit})
            return {"ok": True, "disasm_of": address}

        def __getattr__(self, name):
            if name in _BACKEND_TOOL_NAME_MAP:
                def stub(*args, **kwargs):
                    self._record(name, args, kwargs)
                    return {"ok": True, "stub": name}
                return stub
            raise AttributeError(name)

    return StubBackend()


@pytest.fixture
def server(stub_backend):
    """A SimpleMcpServer wired to the stub backend with a fake session."""
    from tinyghidramcp.server import SimpleMcpServer

    srv = SimpleMcpServer(stub_backend)
    srv._auto_session_id = "sess-fake"
    return srv
