"""Telemetry: pre-dispatch errors, tool calls, session-start, pyghidra.exec body."""

from __future__ import annotations

import json
from pathlib import Path

from tinyghidramcp.server import SimpleMcpServer
from tinyghidramcp.telemetry import from_env


def _read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _telemetry_path(telemetry_dir: Path) -> Path:
    files = list(telemetry_dir.glob("session_*.jsonl"))
    assert len(files) == 1, f"expected one telemetry file, found: {files}"
    return files[0]


def test_session_start_record(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv._auto_session_id = "sess-fake"
    t.emit_session_start(ghidra_version="12.1", git_sha="abc1234", binary_path=None)
    t.close()
    records = _read_jsonl(_telemetry_path(telemetry_dir))
    assert records[0]["event"] == "session_start"
    assert records[0]["ghidra_version"] == "12.1"
    assert records[0]["tinyghidramcp_git_sha"] == "abc1234"
    assert records[0]["session"] == "test-session"


def test_pre_dispatch_json_parse_error(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv.handle_json_line("not json {")
    t.close()
    records = _read_jsonl(_telemetry_path(telemetry_dir))
    rec = records[-1]
    assert rec["status"] == "pre_dispatch_error"
    assert rec["error_code"] == "json_parse_error"
    assert rec["tool"] is None
    assert rec["raw_args_preview"].startswith("not json")


def test_pre_dispatch_tool_not_found(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "no.such.tool", "arguments": {}},
    }))
    t.close()
    rec = _read_jsonl(_telemetry_path(telemetry_dir))[-1]
    assert rec["status"] == "pre_dispatch_error"
    assert rec["error_code"] == "tool_not_found"
    assert rec["requested_tool"] == "no.such.tool"


def test_pre_dispatch_validation_error_on_non_string_name(telemetry_dir, stub_backend):
    """When tools/call is sent with `name` as a non-string, the server emits a
    pre-dispatch validation_error record (tool=null) before refusing the call."""
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": 42, "arguments": {}},
    }))
    t.close()
    rec = _read_jsonl(_telemetry_path(telemetry_dir))[-1]
    assert rec["status"] == "pre_dispatch_error"
    assert rec["error_code"] == "validation_error"
    assert rec["tool"] is None
    assert rec["validation_field"] == "name"
    assert rec["validation_expected"] == "string"


def test_pre_dispatch_validation_error_on_non_object_arguments(telemetry_dir, stub_backend):
    """Same shape when `arguments` is the wrong type."""
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "decompile", "arguments": "not-an-object"},
    }))
    t.close()
    rec = _read_jsonl(_telemetry_path(telemetry_dir))[-1]
    assert rec["status"] == "pre_dispatch_error"
    assert rec["error_code"] == "validation_error"
    assert rec["tool"] == "decompile"
    assert rec["validation_field"] == "arguments"
    assert rec["validation_expected"] == "object"


def test_tool_call_records_args_and_status(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv._auto_session_id = "sess-fake"
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "decompile", "arguments": {"target": "0x401234"}},
    }))
    t.close()
    records = _read_jsonl(_telemetry_path(telemetry_dir))
    tool_call = next(r for r in records if r["event"] == "tool_call" and r.get("tool") == "decompile")
    assert tool_call["status"] == "ok"
    assert tool_call["error_code"] is None
    assert tool_call["args"] == {"target": "0x401234"}


def test_pyghidra_exec_captures_full_code_body(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv._auto_session_id = "sess-fake"
    code_body = "x = currentProgram.getName()\nresult = x.upper()"
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "pyghidra.exec", "arguments": {"code": code_body}},
    }))
    t.close()
    rec = next(
        r for r in _read_jsonl(_telemetry_path(telemetry_dir))
        if r.get("tool") == "pyghidra.exec"
    )
    assert rec["code"] == code_body


def test_long_string_args_get_truncated_but_code_does_not(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv._auto_session_id = "sess-fake"
    huge = "x" * 5000
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "pyghidra.exec", "arguments": {"code": huge}},
    }))
    t.close()
    rec = next(
        r for r in _read_jsonl(_telemetry_path(telemetry_dir))
        if r.get("tool") == "pyghidra.exec"
    )
    # args.code is truncated (huge in args dict)
    assert rec["args_truncated"] is True
    assert len(rec["args"]["code"]) == 1024
    # but the dedicated `code` field captures the full body
    assert rec["code"] == huge


def test_error_telemetry_carries_error_code(telemetry_dir, stub_backend):
    t = from_env()
    srv = SimpleMcpServer(stub_backend, telemetry=t)
    srv._auto_session_id = "sess-fake"
    stub_backend.next_eval_response = {
        "kind": "miss", "is_code": True, "in_section": ".text", "reason": "unanalyzed_code",
    }
    srv.handle_json_line(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "decompile", "arguments": {"target": "0x401abc"}},
    }))
    t.close()
    rec = next(
        r for r in _read_jsonl(_telemetry_path(telemetry_dir))
        if r.get("tool") == "decompile"
    )
    assert rec["status"] == "error"
    assert rec["error_code"] == "not_found_address"
