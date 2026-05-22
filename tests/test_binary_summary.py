"""Curated binary.summary: composes upstream + recon script."""

from __future__ import annotations

import json
from unittest.mock import patch

from tinyghidramcp.binary_summary import curate


UPSTREAM_FIXTURE = {
    "session_id": "sess-fake",
    "filename": "binary",
    "format": "Executable and Linking Format (ELF)",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc",
    "entry_point": "0x401050",
    "image_base": "0x400000",
    "min_address": "0x400000",
    "max_address": "0x410000",
    "read_only": True,
}

RECON_FIXTURE = {
    "sections": [
        {"name": ".text", "start": "0x401000", "end": "0x401fff",
         "size": 4096, "perms": "RX", "initialized": True},
        {"name": ".rodata", "start": "0x402000", "end": "0x402fff",
         "size": 4096, "perms": "R", "initialized": True},
    ],
    "dynamic_deps": ["libc.so.6"],
    "language_hint": "c",
    "security": {"nx": True, "pie": False, "relro": "full", "canary": True, "stripped": False},
    "top_symbols": [
        {"name": "main", "address": "0x401234", "xrefs": 12, "exported": True},
        {"name": "parse_input", "address": "0x401500", "xrefs": 5, "exported": False},
    ],
    "top_symbols_count": 2,
}


def test_curate_merges_upstream_and_recon():
    out = curate(UPSTREAM_FIXTURE, RECON_FIXTURE)
    # Upstream fields preserved (minus session_id)
    assert out["filename"] == "binary"
    assert out["entry_point"] == "0x401050"
    assert out["language_id"] == "x86:LE:64:default"
    assert "session_id" not in out
    # Recon fields surfaced
    assert out["language_hint"] == "c"
    assert out["security"]["nx"] is True
    assert out["security"]["canary"] is True
    assert len(out["sections"]) == 2
    assert out["top_symbols"][0]["name"] == "main"


def _call(server, args=None):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "binary.summary", "arguments": args or {}}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_binary_summary_handler_combines_upstream_and_recon(server, stub_backend):
    stub_backend.binary_summary = lambda session_id: UPSTREAM_FIXTURE
    stub_backend.eval_code = lambda code, *, session_id=None: {"result": RECON_FIXTURE}

    r = _call(server)
    sc = r["structuredContent"]
    assert r["isError"] is False
    assert sc["cached"] is False
    assert sc["filename"] == "binary"
    assert sc["language_hint"] == "c"
    assert sc["security"]["canary"] is True
    assert sc["top_symbols_count"] == 2


def test_binary_summary_caches_for_session(server, stub_backend):
    call_count = {"upstream": 0, "eval": 0}

    def stub_upstream(session_id):
        call_count["upstream"] += 1
        return UPSTREAM_FIXTURE

    def stub_eval(code, *, session_id=None):
        call_count["eval"] += 1
        return {"result": RECON_FIXTURE}

    stub_backend.binary_summary = stub_upstream
    stub_backend.eval_code = stub_eval

    r1 = _call(server)
    r2 = _call(server)
    assert r1["structuredContent"]["cached"] is False
    assert r2["structuredContent"]["cached"] is True
    # Backend called only once even though we hit the tool twice.
    assert call_count["upstream"] == 1
    assert call_count["eval"] == 1
