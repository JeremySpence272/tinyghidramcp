"""Curated binary.summary: ship a one-call recon payload that pays for itself.

Composes upstream ``binary_summary`` (basic metadata) with a single ``eval_code``
call that gathers sections, dynamic dependencies, security flag heuristics,
language/runtime hint, and the top-200 symbols sorted by xref count.

Top-symbols filter follows the design contract:
    exported  OR  (named ∧ ¬synthetic ∧ xref_count > 1)
Sorted by xref count descending; capped at 200. No knobs.
"""

from __future__ import annotations

import textwrap
from typing import Any

# Single pyghidra script that gathers everything not in upstream binary_summary.
# Returned as a dict bound to `result`; the server merges it onto the upstream payload.
_RECON_SCRIPT = textwrap.dedent(
    '''
    fm = program.getFunctionManager()
    sm = program.getSymbolTable()
    mem = program.getMemory()
    ref_mgr = program.getReferenceManager()
    default_space = program.getAddressFactory().getDefaultAddressSpace()

    def _addr_str(a):
        return "0x%x" % a.getOffset()

    # ---- entry_point (upstream's value can be null on stripped binaries) ---
    # Try, in order:
    #   1) flatProgramAPI.getEntryPoint() if available via record (upstream did this)
    #   2) addressed by `_start` symbol
    #   3) any other symbol named `entry` / `main`
    #   4) options(.Program Information).get(ENTRY POINT)
    entry_point = None
    for entry_name in ("_start", "entry", "main"):
        syms = list(sm.getGlobalSymbols(entry_name))
        if not syms:
            syms = list(sm.getSymbols(entry_name))
        for s in syms:
            if s.getAddress().getAddressSpace() == default_space:
                entry_point = _addr_str(s.getAddress())
                break
        if entry_point:
            break
    if entry_point is None:
        # Last resort: iterate external entry points.
        try:
            for addr in sm.getExternalEntryPointIterator():
                if addr.getAddressSpace() == default_space:
                    entry_point = _addr_str(addr)
                    break
        except Exception:
            pass

    # ---- min/max address restricted to the default address space ---------
    # Upstream's program.getMinAddress() / getMaxAddress() iterate every block
    # including Ghidra's synthetic OTHER overlay (where it parks ELF metadata
    # blocks like `_elfSectionHeaders`). We want the real loaded range.
    default_min = None
    default_max = None
    for block in mem.getBlocks():
        start = block.getStart()
        if start.getAddressSpace() != default_space:
            continue
        end = block.getEnd()
        if default_min is None or start.compareTo(default_min) < 0:
            default_min = start
        if default_max is None or end.compareTo(default_max) > 0:
            default_max = end
    min_address = _addr_str(default_min) if default_min else None
    max_address = _addr_str(default_max) if default_max else None

    # ---- sections ----------------------------------------------------------
    sections = []
    for block in mem.getBlocks():
        flags = []
        if block.isRead():    flags.append("R")
        if block.isWrite():   flags.append("W")
        if block.isExecute(): flags.append("X")
        sections.append({
            "name": str(block.getName()),
            "start": _addr_str(block.getStart()),
            "end": _addr_str(block.getEnd()),
            "size": int(block.getSize()),
            "perms": "".join(flags),
            "initialized": bool(block.isInitialized()),
        })

    # ---- dynamic deps (best-effort via program properties / external libs) -
    dynamic_deps = []
    try:
        ext_mgr = program.getExternalManager()
        for lib in ext_mgr.getExternalLibraryNames():
            dynamic_deps.append(str(lib))
    except Exception:
        pass

    # ---- language / runtime hint via symbol patterns -----------------------
    language_hint = "c"
    sample_names = []
    sym_iter = sm.getDefinedSymbols()
    counter = 0
    has_go = False
    has_rust = False
    has_cpp = False
    has_canary = False
    for sym in sym_iter:
        name = str(sym.getName())
        if counter < 200:
            sample_names.append(name)
        counter += 1
        if name == "__stack_chk_fail":
            has_canary = True
        if name.startswith("runtime.") or name == "go.buildid" or name.startswith("go:itab."):
            has_go = True
        if name.startswith("_RN") or name.startswith("_R$") or "$LT$" in name or name.startswith("rust_") or "rust_eh_personality" in name:
            has_rust = True
        if name.startswith("_Z") and len(name) > 3:
            has_cpp = True
        if counter > 50000:
            break
    if has_go:
        language_hint = "go"
    elif has_rust:
        language_hint = "rust"
    elif has_cpp:
        language_hint = "c++"

    # ---- security flag heuristics ------------------------------------------
    # NX: any executable block with W flag = no NX. Conversely, if no executable
    # block is writable, NX is enabled.
    nx_enabled = not any(b.isExecute() and b.isWrite() for b in mem.getBlocks())
    # RELRO: presence of a block named ".got.plt" without W after relocation is
    # the canonical marker; best-effort here -- check for a non-writable .got.
    relro = "none"
    got_block = None
    got_plt_block = None
    for b in mem.getBlocks():
        if str(b.getName()) == ".got":
            got_block = b
        elif str(b.getName()) == ".got.plt":
            got_plt_block = b
    if got_block is not None and not got_block.isWrite():
        relro = "partial"
        if got_plt_block is None or not got_plt_block.isWrite():
            relro = "full"
    # PIE: heuristic: image base < 0x400000 typically indicates PIE (load addr 0)
    image_base_offset = program.getImageBase().getOffset()
    pie = image_base_offset < 0x400000
    # Stripped: presence of a `.symtab` named block, or FUN_*-only naming.
    stripped = True
    for sym in sm.getDefinedSymbols():
        name = str(sym.getName())
        if name and not name.startswith("FUN_") and not name.startswith("LAB_") and not name.startswith("DAT_"):
            stripped = False
            break

    security = {
        "nx": bool(nx_enabled),
        "pie": bool(pie),
        "relro": relro,
        "canary": bool(has_canary),
        "stripped": bool(stripped),
    }

    # ---- top symbols by xref count -----------------------------------------
    # Filter: exported OR (named ∧ ¬synthetic ∧ xref_count > 1).
    # Sorted by xref count descending; cap 200.
    SYNTHETIC_PREFIXES = ("FUN_", "LAB_", "DAT_", "SUB_", "EXT_", "thunk_FUN_")
    candidates = []
    for fn in fm.getFunctions(True):
        name = str(fn.getName())
        synthetic = any(name.startswith(p) for p in SYNTHETIC_PREFIXES)
        entry = fn.getEntryPoint()
        # Count xrefs to the function entry.
        n_xrefs = 0
        for _ in ref_mgr.getReferencesTo(entry):
            n_xrefs += 1
            if n_xrefs > 1000:
                break
        # Exported check: is the function in the exported-symbols table?
        is_exported = False
        try:
            primary = sm.getPrimarySymbol(entry)
            if primary is not None and primary.isExternalEntryPoint():
                is_exported = True
        except Exception:
            pass
        if is_exported or (name and not synthetic and n_xrefs > 1):
            candidates.append({
                "name": name,
                "address": _addr_str(entry),
                "xrefs": int(n_xrefs),
                "exported": bool(is_exported),
            })
    candidates.sort(key=lambda c: c["xrefs"], reverse=True)
    top_symbols = candidates[:200]

    result = {
        "sections": sections,
        "dynamic_deps": dynamic_deps,
        "language_hint": language_hint,
        "security": security,
        "top_symbols": top_symbols,
        "top_symbols_count": len(top_symbols),
        "entry_point": entry_point,
        "min_address": min_address,
        "max_address": max_address,
    }
    _ = result
    '''
).strip()


def curate(
    upstream: dict[str, Any],
    recon: dict[str, Any],
) -> dict[str, Any]:
    """Merge upstream basic metadata with the recon script's output."""
    # Pull the canonical fields from upstream, drop session_id (server hides it).
    # Note: a `runtime_image_base` field would belong here when/if we support
    # rebasing -- in headless mode without rebase, file image base == runtime
    # image base, so a second field would be a lie. Add it back if/when we
    # expose `program.image_base.set`.
    out: dict[str, Any] = {
        "filename": upstream.get("filename"),
        "format": upstream.get("format"),
        "language_id": upstream.get("language_id"),
        "compiler_spec_id": upstream.get("compiler_spec_id"),
        "entry_point": upstream.get("entry_point"),
        "image_base": upstream.get("image_base"),
        "min_address": upstream.get("min_address"),
        "max_address": upstream.get("max_address"),
        "read_only": upstream.get("read_only"),
    }
    out.update(recon)
    # Recon's entry_point / min_address / max_address override upstream only
    # when recon actually produced a value. Upstream returns null on stripped
    # binaries (entry_point) and leaks Ghidra's OTHER overlay into max_address;
    # recon corrects both, restricted to the default address space.
    for k in ("entry_point", "min_address", "max_address"):
        if recon.get(k) is None and upstream.get(k) is not None:
            out[k] = upstream[k]
    return out


def build_recon_script() -> str:
    return _RECON_SCRIPT
