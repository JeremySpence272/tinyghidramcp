"""Hand-written long-form docs for every tool, returned by ``meta.help``.

Address-format note (applies across all tools)
----------------------------------------------
Address strings in responses come in two forms depending on the upstream
producer:
  - ``"0x..."`` with prefix (used by binary.summary's entry_point and
    sections[].start/end after our normalization)
  - ``"NNNNNNNN"`` zero-padded hex without prefix (the default Ghidra
    ``Address.toString()`` form, used by most other tools)

Both represent the same canonical value. When comparing addresses across
tool responses, normalize with ``int(addr, 16)`` rather than string
equality. We don't unify the format at the server because it would require
walking every response dict with key-name heuristics, which is invasive
and error-prone.



Each entry has:
- ``description``: full prose (longer than the one-line tools/list version)
- ``parameters``: list of ``{name, type, description, required}``
- ``examples``: list of ``{args, result_summary}``
- ``pyghidra_alternative``: a one-line copy-pasteable pyghidra.exec snippet
  that does the same thing (or close enough to teach the agent the API)

Don't auto-generate from docstrings -- the value is in writing these as if
talking to an agent that's about to use the tool right now.
"""

from __future__ import annotations

from typing import Any

DOCS: dict[str, dict[str, Any]] = {
    "binary.summary": {
        "description": (
            "Recon-in-one-call. Returns the open program's language id, executable "
            "format, image base, entry point, sections (with R/W/X flags), dynamic "
            "dependencies, security flags (NX / PIE / RELRO / canary / stripped), "
            "language/runtime hint (c / c++ / go / rust), and the top-200 symbols "
            "filtered by `exported OR (named AND not-synthetic AND xrefs > 1)`, "
            "sorted by xref count descending. Cached for the session; subsequent "
            "calls return `cached: true` without re-running. Call this once at the "
            "start of every session before anything else."
        ),
        "parameters": [],
        "examples": [
            {
                "args": {},
                "result_summary": (
                    "{language_id: 'x86:LE:64:default', entry_point: '0x401050', "
                    "language_hint: 'c', security: {nx: true, pie: true, "
                    "relro: 'full', canary: true, stripped: false}, "
                    "top_symbols: [{name: 'main', address: '0x401234', xrefs: 12}, ...], "
                    "cached: false}"
                ),
            }
        ],
        "pyghidra_alternative": (
            "currentProgram.getLanguageID(), currentProgram.getImageBase(), "
            "[(s.getName(), '0x%x' % s.getAddress().getOffset()) for s in sm.getDefinedSymbols()][:200]"
        ),
    },
    "search.functions": {
        "description": (
            "Search functions by name. Default is regex (Python `re.search`); set "
            "`exact=true` for literal string match. Regex mode is **case-sensitive**; "
            "the upstream substring fallback (via `exact=true`) is case-INsensitive. "
            "An empty or missing `name` returns the full function list (paginated "
            "by `limit`) -- useful for enumeration. "
            "Returns name, entry address, signature, and a `regex: true` flag on the "
            "default path."
        ),
        "parameters": [
            {"name": "name", "type": "string", "description": "Regex pattern (or literal if exact=true)", "required": True},
            {"name": "limit", "type": "integer", "description": "Max results (default 50)", "required": False},
            {"name": "exact", "type": "boolean", "description": "Disable regex; literal match", "required": False},
        ],
        "examples": [
            {"args": {"name": "^parse_"}, "result_summary": "matches parse_args, parse_input, parse_config"},
            {"args": {"name": "main", "exact": True}, "result_summary": "exact: one hit for 'main' at 0x401234"},
        ],
        "pyghidra_alternative": (
            "[(f.getName(), '0x%x' % f.getEntryPoint().getOffset()) for f in fm.getFunctions(True) if 'parse_' in f.getName()]"
        ),
    },
    "search.strings": {
        "description": (
            "Search defined strings in the program. Returns address, length, and content "
            "for each hit. Strings shorter than min_length are skipped (typical default 4)."
        ),
        "parameters": [
            {"name": "query", "type": "string", "description": "Substring or regex to match", "required": False},
            {"name": "limit", "type": "integer", "description": "Max results (default 50)", "required": False},
            {"name": "offset", "type": "integer", "description": "Skip this many before returning results", "required": False},
        ],
        "examples": [
            {"args": {"query": "flag"}, "result_summary": "[{address: '0x403100', value: 'flag{...}'}, ...]"},
            {"args": {"query": "%s"}, "result_summary": "format-string strings used in printf-family calls"},
        ],
        "pyghidra_alternative": (
            "[(d.getAddress(), str(d.getValue())) for d in listing.getDefinedData(True) "
            "if d.hasStringValue() and 'flag' in str(d.getValue())]"
        ),
    },
    "decompile": {
        "description": (
            "Decompile one function. `target` accepts a hex address "
            "(`0x401234` or `401234`) or a symbol name (`main`, `main.main`, `_Znwm`). "
            "The server auto-resolves: if you pass an address inside a function, it "
            "decompiles the containing function and tells you via `address_adjusted`. "
            "PLT thunks are resolved to their target. Unanalysed code / data / "
            "out-of-image misses return a structured error with `next_action` and a "
            "`pyghidra_hint` for the agent's next move."
        ),
        "parameters": [
            {"name": "target", "type": "string", "description": "Hex address or symbol name", "required": True},
            {"name": "timeout_secs", "type": "integer", "description": "Decompiler timeout (default 30)", "required": False},
            {"name": "max_lines", "type": "integer", "description": "Truncate to this many lines (default 800; hard ceiling 4000)", "required": False},
        ],
        "examples": [
            {"args": {"target": "main"}, "result_summary": "decompiles `main`; address_adjusted shows symbol_lookup"},
            {"args": {"target": "0x40123a"}, "result_summary": "mid-function offset; adjusts to containing function entry"},
        ],
        "pyghidra_alternative": (
            "decompAPI.decompileFunction(fm.getFunctionAt(toAddr(0x401234)), 30, monitor).getDecompiledFunction().getC()"
        ),
    },
    "decompile.batch": {
        "description": (
            "Decompile many functions in one call. Returns a dict keyed by the input "
            "target string (exactly what you passed). Per-target failures are recorded "
            "as error entries; the whole call still succeeds. Use this when you've "
            "identified N candidate functions from `search.functions` or `xrefs.to` "
            "and want them all without N round-trips."
        ),
        "parameters": [
            {"name": "targets", "type": "array", "description": "List of addresses or names", "required": True},
            {"name": "max_lines_each", "type": "integer", "description": "Per-function line cap (default 200)", "required": False},
        ],
        "examples": [
            {
                "args": {"targets": ["main", "parse_args", "0x405000"]},
                "result_summary": "{'main': {...}, 'parse_args': {...}, '0x405000': {...}}",
            }
        ],
        "pyghidra_alternative": (
            "{name: decompAPI.decompileFunction(fm.getFunctionAt(toAddr(addr)), 30, monitor).getDecompiledFunction().getC() "
            "for name, addr in [('main', 0x401234), ('parse_args', 0x405000)]}"
        ),
    },
    "disassemble": {
        "description": (
            "Disassemble a function (when `address` resolves to a function) or a byte "
            "range (otherwise). Every line carries the absolute address and the "
            "demangled symbol. Same address-tolerance as `decompile`."
        ),
        "parameters": [
            {"name": "address", "type": "string", "description": "Hex address or symbol name", "required": True},
            {"name": "limit", "type": "integer", "description": "Max instructions (default 100)", "required": False},
        ],
        "examples": [
            {"args": {"address": "main"}, "result_summary": "function-scope disassembly of main"},
            {"args": {"address": "0x401000", "limit": 20}, "result_summary": "20 instructions starting at 0x401000"},
        ],
        "pyghidra_alternative": (
            "[str(listing.getInstructionAt(toAddr(addr))) for addr in range(0x401000, 0x401100, 4)]"
        ),
    },
    "xrefs.to": {
        "description": (
            "Find references TO an address. Code-only by default; set `include_data=true` "
            "to include data references. The address can be a function entry, an "
            "instruction offset, or a data label. Returns from-address, type "
            "(call / jump / read / write), and the containing function name when applicable."
        ),
        "parameters": [
            {"name": "address", "type": "string", "description": "Target address or symbol", "required": False},
            {"name": "limit", "type": "integer", "description": "Max results (default 100)", "required": False},
        ],
        "examples": [
            {"args": {"address": "0x401234"}, "result_summary": "callers of 0x401234"},
        ],
        "pyghidra_alternative": (
            "[(r.getFromAddress(), str(r.getReferenceType())) for r in "
            "currentProgram.getReferenceManager().getReferencesTo(toAddr(0x401234))]"
        ),
    },
    "xrefs.from": {
        "description": (
            "Find references FROM an address: where does this instruction or data label "
            "send control or data? Mirror of `xrefs.to`."
        ),
        "parameters": [
            {"name": "address", "type": "string", "description": "Source address or symbol", "required": False},
            {"name": "limit", "type": "integer", "description": "Max results (default 100)", "required": False},
        ],
        "examples": [
            {"args": {"address": "main"}, "result_summary": "every call/jump/data-ref out of main"},
        ],
        "pyghidra_alternative": (
            "[(r.getToAddress(), str(r.getReferenceType())) for r in "
            "currentProgram.getReferenceManager().getReferencesFrom(toAddr(0x401234))]"
        ),
    },
    "callgraph": {
        "description": (
            "Find call-graph paths BETWEEN two specific functions. This is point-to-point: "
            "you supply both `source_function` AND `target_function`, and the tool returns "
            "the paths connecting them as flat (caller_addr, callee_addr, callsite_addr, "
            "callee_name) edges. This is NOT an outbound walk -- if you want to know "
            "`what does X call?` use `xrefs.from`; for `who calls X?` use `xrefs.to`. "
            "For arbitrary-depth or filtered traversal, use `pyghidra.exec`."
        ),
        "parameters": [
            {"name": "source_function", "type": "string", "description": "Hex address or name of starting function (REQUIRED)", "required": True},
            {"name": "target_function", "type": "string", "description": "Hex address or name of ending function (REQUIRED)", "required": True},
            {"name": "max_depth", "type": "integer", "description": "Max edges to traverse (default 4)", "required": False},
            {"name": "limit", "type": "integer", "description": "Max paths returned", "required": False},
        ],
        "examples": [
            {
                "args": {"source_function": "main", "target_function": "system"},
                "result_summary": "paths from main to system, including intermediate calls",
            }
        ],
        "pyghidra_alternative": (
            "# outbound walk from main, depth 3:\n"
            "from collections import deque\n"
            "start = fm.getFunctionAt(toAddr('0x401234'))\n"
            "visited = set(); q = deque([(start, 0)]); edges = []\n"
            "while q:\n"
            "    fn, d = q.popleft()\n"
            "    if d >= 3 or fn in visited: continue\n"
            "    visited.add(fn)\n"
            "    for callee in fn.getCalledFunctions(monitor):\n"
            "        edges.append((fn.getName(), callee.getName()))\n"
            "        q.append((callee, d+1))\n"
            "result = edges"
        ),
    },
    "resolve": {
        "description": (
            "Resolve a name or expression to one or more candidate addresses. Useful "
            "when you have a symbol from `nm` or `objdump` and want to confirm Ghidra "
            "sees it. Returns address, section, type (function / data / import / "
            "export), and a confidence score per candidate."
        ),
        "parameters": [
            {"name": "query", "type": "string", "description": "Symbol name or expression", "required": True},
        ],
        "examples": [
            {"args": {"query": "main"}, "result_summary": "[{address: '0x401234', type: 'function', confidence: 1.0}]"},
        ],
        "pyghidra_alternative": (
            "[('0x%x' % s.getAddress().getOffset(), str(s.getSymbolType())) for s in sm.getSymbols('main')]"
        ),
    },
    "pyghidra.exec": {
        "description": (
            "Run arbitrary Python with the open program bound. No sandbox; runs as "
            "root in the agent's container with full Ghidra-API and filesystem "
            "access. Globals persist across calls in the same session, so you can "
            "build up state. Bound names: `currentProgram`, `currentAddress` "
            "(sticky), `monitor`, `flatAPI`, `decompAPI`, `listing`, `fm`, `sm`, "
            "`mem`, `cache` (with `cache.invalidate()` to flush decompile cache). "
            "Auto-detects single-line expression vs multi-line script: an expression "
            "returns its value as `result`; a script can set `result` explicitly.\n\n"
            "**Budget your loops.** This tool enforces a wall-clock timeout (default "
            "60 s, max 600 s via `timeout_sec`). Scripts that exceed the budget are "
            "aborted and the persistent globals are rolled back to their pre-call "
            "state. The Ghidra worker thread itself may continue running in the JVM "
            "until the call completes naturally -- we can't safely interrupt mid-call. "
            "Subsequent pyghidra.exec calls will fast-fail with error_code=state "
            "until the worker completes. For brute-force scans, fuzzing, or anything "
            "you'd `for i in range(10**6)` over: write the script to a file via the "
            "`Write` tool and run it via bash. Use `pyghidra.exec` for analytical "
            "queries, not for compute.\n\n"
            "**Rollback is shallow.** The snapshot captures STATE's *keys* and "
            "references its values by identity. If a timed-out script mutated a "
            "mutable global IN PLACE (e.g. `x.append(4)` on a pre-existing list), "
            "that mutation survives the rollback -- only key-level adds/removes/"
            "reassignments are reverted. To be safe across timeout boundaries, "
            "rebind variables (`x = x + [4]`) rather than mutating them in place.\n\n"
            "**`sys.exit()` is intercepted.** Calling `sys.exit()` from inside "
            "pyghidra.exec is converted to error_code=unsupported instead of "
            "killing the server. Don't rely on it as a flow-control mechanism."
        ),
        "parameters": [
            {"name": "code", "type": "string", "description": "Python source code", "required": True},
            {"name": "timeout_sec", "type": "number", "description": "Wall-clock timeout in seconds (default 60, max 600)", "required": False},
        ],
        "examples": [
            {
                "args": {"code": "fm.getFunctionAt(toAddr(0x401234)).getName()"},
                "result_summary": "expression returns 'main'",
            },
            {
                "args": {"code": "result = [f.getName() for f in fm.getFunctions(True) if 'aes' in f.getName().lower()]"},
                "result_summary": "script returns list of AES-related function names",
            },
            {
                "args": {"code": "import time; time.sleep(120)", "timeout_sec": 5},
                "result_summary": "error_code=timeout; globals rolled back",
            },
        ],
        "pyghidra_alternative": "(this IS the pyghidra escape hatch)",
    },
    "meta.help": {
        "description": (
            "Return long-form documentation for any named tool. Use this when "
            "`tools/list` description is too terse, or when you want a concrete "
            "example invocation, or when you want the `pyghidra.exec` equivalent."
        ),
        "parameters": [
            {"name": "tool", "type": "string", "description": "Name of the tool to look up", "required": True},
        ],
        "examples": [
            {"args": {"tool": "decompile"}, "result_summary": "full docs + examples for `decompile`"},
        ],
        "pyghidra_alternative": "(meta tool; no pyghidra equivalent)",
    },
}


def get(tool: str) -> dict[str, Any] | None:
    """Look up the hand-written entry for one tool. Returns None if unknown."""
    return DOCS.get(tool)
