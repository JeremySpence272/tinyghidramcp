"""decompile cache: LRU keyed by resolved address; cached flag on responses."""

from __future__ import annotations

import json

from tinyghidramcp.decompile_cache import DecompileCache


def _call(server, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    return json.loads(server.handle_json_line(json.dumps(req)))["result"]


def test_cache_unit_basic():
    cache = DecompileCache(max_bytes=10_000)
    assert cache.get(("0x401234", 30)) is None
    cache.put(("0x401234", 30), {"decompile": "x" * 100})
    assert cache.get(("0x401234", 30))["decompile"] == "x" * 100
    assert cache.hits == 1
    assert cache.misses == 1
    cache.invalidate()
    assert cache.get(("0x401234", 30)) is None


def test_cache_unit_lru_eviction():
    cache = DecompileCache(max_bytes=300)
    cache.put(("a",), {"x": "y" * 200})
    cache.put(("b",), {"x": "y" * 200})  # should evict ("a",)
    assert cache.get(("a",)) is None
    assert cache.get(("b",)) is not None


def test_decompile_first_call_misses_second_hits(server, stub_backend):
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    # First call -> cached=False
    r1 = _call(server, "decompile", {"function_start": "0x401234"})
    sc1 = r1["structuredContent"]
    assert sc1["cached"] is False

    # Second call -> cached=True. Stub returns the same resolver response.
    r2 = _call(server, "decompile", {"function_start": "0x401234"})
    sc2 = r2["structuredContent"]
    assert sc2["cached"] is True


def test_two_different_inputs_resolving_to_same_addr_share_cache(server, stub_backend):
    """Address tolerance canonicalises before the cache key."""
    # First request: name 'main' -> 0x401234
    stub_backend.next_eval_response = {
        "kind": "exact", "reason": "symbol_lookup", "address": "0x401234", "name": "main",
    }
    r1 = _call(server, "decompile", {"function_start": "main"})
    assert r1["structuredContent"]["cached"] is False

    # Second request: hex address that resolves to the same function
    stub_backend.next_eval_response = {
        "kind": "exact", "address": "0x401234", "name": "main",
    }
    r2 = _call(server, "decompile", {"function_start": "0x401234"})
    assert r2["structuredContent"]["cached"] is True


def test_pyghidra_exec_cache_invalidate_flushes_decompile_cache(server, stub_backend):
    """Wire-up: when pyghidra.exec calls cache.invalidate(), decompile cache empties."""
    # Prime cache
    stub_backend.next_eval_response = {"kind": "exact", "address": "0x401234", "name": "main"}
    _call(server, "decompile", {"function_start": "0x401234"})
    assert server._decompile_cache.entries == 1

    # The stub's eval_code ignores the wrapped script; flip the invalidate flag
    # by hand and then call pyghidra.exec to trigger the flush path.
    from tinyghidramcp import _pyghidra_session
    _pyghidra_session.INVALIDATE_REQUESTED = True
    r = _call(server, "pyghidra.exec", {"code": "1"})
    sc = r["structuredContent"]
    assert sc["cache_invalidate_requested"] is True
    assert sc["decompile_cache_flushed_entries"] == 1
    assert server._decompile_cache.entries == 0
