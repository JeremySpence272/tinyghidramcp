"""Address-tolerance pipeline.

When an agent passes an address that isn't a function-start, we don't just fail
with ``"Function not found"``. We run a 5-step pipeline that auto-adjusts to the
containing function, resolves PLT thunks, optionally runs bounded auto-analysis,
and -- on a true miss -- returns a structured payload the agent can act on:
``in_section``, ``is_code``, ``nearest_function``, plus a ``next_action`` /
``pyghidra_hint``.

Steps:
  1. Exact: ``getFunctionAt(addr)`` returns a function -> use it.
  2. Containing: ``getFunctionContaining(addr)`` returns a function -> use its
     entry point, mark ``address_adjusted.reason = "mid_function"``.
  3. PLT thunk: address is in ``.plt`` / ``.plt.sec`` / ``.plt.got`` / ``.got.plt``
     -> follow the call/jump reference to the target function.
  4. Bounded auto-analysis: when address is in an executable block but unanalysed,
     try ``flat_api.disassemble`` + ``flat_api.createFunction`` with a 10 s wall
     cap. On success: ``address_adjusted.reason = "auto_analyzed"``. On cap hit:
     raise ``state`` error with a pyghidra hint to extend.
  5. Structured miss: report ``is_code``, ``in_section``, ``nearest_function``.
"""

from __future__ import annotations

import concurrent.futures
import textwrap
from typing import Any

from .errors import ToolError

# Wall cap for step 4 auto-analysis. Non-negotiable per design: never block
# an agent loop on analysis longer than this.
AUTO_ANALYZE_WALL_SEC = 10

_RESOLVE_SCRIPT = textwrap.dedent(
    '''
    # Inputs: _addr (str hex like "0x401234", decimal int, or a symbol name)
    # Outputs: bound `result` dict with one of:
    #   {"kind": "exact"|"containing"|"plt_thunk", "address": "0x..", "name": "..", "reason": ..., "via": ..}
    #   {"kind": "miss", "is_code": bool, "in_section": str|None, "nearest_function": "0x..", "reason": ...}

    def _is_addresslike(v):
        if isinstance(v, int):
            return True
        s = str(v).strip().lower()
        if s.startswith("0x"):
            return True
        try:
            int(s, 16 if any(c in "abcdef" for c in s) else 10)
            return True
        except ValueError:
            return False

    def _parse_addr(v):
        if isinstance(v, int):
            return v
        s = str(v).strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        try:
            return int(s, 16) if any(c in "abcdef" for c in s) else int(s)
        except ValueError:
            return int(s, 16)

    _name_lookup_used = False
    if _is_addresslike(_addr):
        addr_int = _parse_addr(_addr)
    else:
        # Symbol name lookup. Three sources, merged:
        #   1) Global symbols (st.getGlobalSymbols)
        #   2) Any-namespace symbols (st.getSymbols)
        #   3) Function manager scan by name (catches PLT thunks that aren't
        #      surfaced in the symbol table when an external of the same name
        #      shadows them)
        st = program.getSymbolTable()
        sym_candidates = list(st.getGlobalSymbols(str(_addr)))
        if not sym_candidates:
            sym_candidates = list(st.getSymbols(str(_addr)))

        # Fallback: if all symbol-table candidates are external, walk the
        # function manager for non-external functions with the same name.
        fn_fallbacks = []
        if not sym_candidates or all(bool(s.isExternal()) for s in sym_candidates):
            for fn in program.getFunctionManager().getFunctions(True):
                if str(fn.getName()) == str(_addr) and not fn.isExternal():
                    fn_fallbacks.append(fn)

        if not sym_candidates and not fn_fallbacks:
            result = {"kind": "miss", "reason": "name_not_found",
                      "is_code": False, "in_section": None,
                      "name": str(_addr)}
            addr_int = None
        else:
            # Rank candidates: prefer non-external function-manager hits
            # (real PLT thunks), then non-external symbols, then anything else.
            # Each entry is (rank, address_offset_int, debug_label).
            ranked = []
            for fn in fn_fallbacks:
                ranked.append((0, fn.getEntryPoint().getOffset(), "fn_manager"))
            for sym in sym_candidates:
                is_fn = str(sym.getSymbolType()) == "Function"
                is_external = bool(sym.isExternal())
                if is_fn and not is_external:
                    rank = 1
                elif is_fn:
                    rank = 2
                elif not is_external:
                    rank = 3
                else:
                    rank = 4
                ranked.append((rank, sym.getAddress().getOffset(), "sym_table"))
            ranked.sort(key=lambda t: t[0])
            addr_int = ranked[0][1]
            _name_lookup_used = True

    if addr_int is not None and addr_int > 0x7fffffffffffffff:
        # Java's long maxes out at 2^63-1; Ghidra's AddressFactory.getAddress
        # raises OverflowError beyond that. Reject as bad_args before the JNI
        # boundary so the agent gets a clear message instead of an opaque crash.
        result = {"kind": "miss", "reason": "address_overflow",
                  "is_code": False, "in_section": None,
                  "requested": str(_addr)}
        addr_int = None

    if addr_int is not None:
        try:
            addr_obj = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_int)
        except OverflowError:
            result = {"kind": "miss", "reason": "address_overflow",
                      "is_code": False, "in_section": None,
                      "requested": str(_addr)}
            addr_int = None

    if addr_int is not None:
        fm = program.getFunctionManager()
        mem = program.getMemory()

        def _addr_str(a):
            return "0x%x" % a.getOffset()

        exact = fm.getFunctionAt(addr_obj)
        if exact is not None:
            result = {"kind": "exact",
                      "address": _addr_str(exact.getEntryPoint()),
                      "name": str(exact.getName())}
            if _name_lookup_used:
                result["reason"] = "symbol_lookup"
        else:
            containing = fm.getFunctionContaining(addr_obj)
            if containing is not None:
                result = {"kind": "containing",
                          "reason": "symbol_lookup" if _name_lookup_used else "mid_function",
                          "address": _addr_str(containing.getEntryPoint()),
                          "name": str(containing.getName())}
            else:
                block = mem.getBlock(addr_obj)
                block_name = str(block.getName()) if block is not None else None
                plt_blocks = (".plt", ".plt.sec", ".plt.got", ".got.plt")
                if block_name in plt_blocks:
                    ref_mgr = program.getReferenceManager()
                    target = None
                    for ref in ref_mgr.getReferencesFrom(addr_obj):
                        rt = ref.getReferenceType()
                        if rt.isCall() or rt.isJump():
                            target_fn = fm.getFunctionAt(ref.getToAddress())
                            if target_fn is not None:
                                target = target_fn
                                break
                    if target is not None:
                        result = {"kind": "plt_thunk", "reason": "plt_thunk",
                                  "address": _addr_str(target.getEntryPoint()),
                                  "name": str(target.getName()),
                                  "via": block_name}
                    else:
                        result = {"kind": "miss", "is_code": True,
                                  "in_section": block_name,
                                  "reason": "plt_thunk_unresolved"}
                elif block is not None and block.isExecute():
                    # Step 4 deferred: would run bounded auto-analysis here.
                    result = {"kind": "miss", "is_code": True,
                              "in_section": block_name,
                              "reason": "unanalyzed_code"}
                elif block is not None:
                    result = {"kind": "miss", "is_code": False,
                              "in_section": block_name,
                              "reason": "data"}
                else:
                    # Walk down to find the nearest function below addr.
                    nearest = None
                    try:
                        fn_iter = fm.getFunctionsNoStubs(False)
                        prev = None
                        for fn in fn_iter:
                            if fn.getEntryPoint().getOffset() > addr_int:
                                nearest = prev
                                break
                            prev = fn
                        else:
                            nearest = prev
                    except Exception:
                        nearest = None
                    result = {"kind": "miss", "is_code": False,
                              "in_section": None,
                              "reason": "out_of_image",
                              "nearest_function":
                                  _addr_str(nearest.getEntryPoint()) if nearest else None}
    _ = result
    '''
).strip()


_AUTO_ANALYZE_SCRIPT = textwrap.dedent(
    '''
    # Step 4: disassemble and try to create a function at the address.
    # Inputs: _addr (same shape as the main resolver script).
    # Outputs: bound `result` matching the main resolver's hit/miss shape.

    def _parse_addr(v):
        if isinstance(v, int):
            return v
        s = str(v).strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        try:
            return int(s, 16) if any(c in "abcdef" for c in s) else int(s)
        except ValueError:
            return int(s, 16)

    addr_int = _parse_addr(_addr)
    addr_obj = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_int)
    fm = program.getFunctionManager()

    try:
        flat_api.disassemble(addr_obj)
    except Exception:
        pass
    try:
        fn = flat_api.createFunction(addr_obj, None)
    except Exception:
        fn = None

    # Re-check via the function manager.
    fn = fn or fm.getFunctionAt(addr_obj) or fm.getFunctionContaining(addr_obj)
    if fn is not None:
        result = {"kind": "exact", "reason": "auto_analyzed",
                  "address": "0x%x" % fn.getEntryPoint().getOffset(),
                  "name": str(fn.getName())}
    else:
        result = {"kind": "miss", "is_code": True,
                  "in_section": None, "reason": "unanalyzed_code"}
    _ = result
    '''
).strip()


def _run_auto_analyze(backend: Any, session_id: str, address: Any) -> dict[str, Any]:
    """Run step-4 auto-analysis with a hard wall cap.

    Returns the resolver-shape dict. Raises ToolError(error_code="state") if
    the analysis didn't complete within ``AUTO_ANALYZE_WALL_SEC`` seconds.
    """
    code = f"_addr = {address!r}\n{_AUTO_ANALYZE_SCRIPT}"
    # Use a single-thread executor so we can enforce a wall cap. On timeout we
    # abandon the future; the underlying Ghidra analysis may complete in the
    # background (next call sees its effects), or it may not. Either is fine
    # for an agent loop; what we never do is block longer than the cap.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(backend.eval_code, code, session_id=session_id)
        try:
            raw = fut.result(timeout=AUTO_ANALYZE_WALL_SEC)
        except concurrent.futures.TimeoutError as exc:
            raise ToolError(
                f"auto-analysis exceeded {AUTO_ANALYZE_WALL_SEC}s wall cap",
                error_code="state",
                next_action=(
                    f"step-4 auto-analysis hit the {AUTO_ANALYZE_WALL_SEC}s cap. "
                    "Call `pyghidra.exec` with a larger budget: "
                    "`flatAPI.disassemble(toAddr(<addr>)); "
                    "flatAPI.createFunction(toAddr(<addr>), None)`."
                ),
                pyghidra_hint=(
                    f"flatAPI.disassemble(toAddr({address!r})); "
                    f"flatAPI.createFunction(toAddr({address!r}), None)"
                ),
            ) from exc
    result = raw.get("result") if isinstance(raw, dict) else raw
    if not isinstance(result, dict):
        raise ToolError(
            f"auto-analyze step returned unexpected shape: {result!r}",
            error_code="internal",
        )
    return result


def resolve(backend: Any, session_id: str, address: Any) -> dict[str, Any]:
    """Run the resolution pipeline; return the structured `result` dict.

    Raises ToolError on a hard miss (the agent gets a structured error response).
    On a hit, returns ``{"kind": "exact"|"containing"|"plt_thunk", "address":
    "0xNNN", "name": "...", "reason": ..., "via": ...}``.
    """
    code = f"_addr = {address!r}\n{_RESOLVE_SCRIPT}"
    raw = backend.eval_code(code, session_id=session_id)
    # eval_code returns {"result": <the bound `result`>}; tolerate both shapes
    result = raw.get("result") if isinstance(raw, dict) else raw
    if not isinstance(result, dict):
        raise ToolError(
            f"address-tolerance pipeline returned unexpected shape: {result!r}",
            error_code="internal",
        )

    kind = result.get("kind")
    if kind in {"exact", "containing", "plt_thunk"}:
        return result

    # Step 4: when the first pass returned `unanalyzed_code`, run bounded
    # auto-analysis (10s cap) and retry. Surface the second-pass result.
    if kind == "miss" and result.get("reason") == "unanalyzed_code":
        result = _run_auto_analyze(backend, session_id, address)
        if result.get("kind") in {"exact", "containing", "plt_thunk"}:
            return result
        # Fall through to the structured-miss handling below with the new result.

    # Miss: build a structured ToolError.
    if kind == "miss":
        in_section = result.get("in_section")
        is_code = bool(result.get("is_code"))
        reason = result.get("reason", "not_found")
        message = f"no function found for {address!r}"

        if reason == "address_overflow":
            raise ToolError(
                f"address {address!r} exceeds the 64-bit signed range and cannot "
                "be a valid virtual address",
                error_code="bad_args",
                next_action=(
                    "check `binary.summary` for the program's image base and "
                    "address range; valid addresses fit in a 63-bit unsigned int."
                ),
                pyghidra_hint=(
                    "currentProgram.getMinAddress(), currentProgram.getMaxAddress()"
                ),
                field="address",
                requested=str(address),
            )

        if reason == "name_not_found":
            raise ToolError(
                f"no symbol named {address!r}",
                error_code="not_found_name",
                next_action=(
                    "no such symbol; try `search.functions` with a substring "
                    "or `pyghidra.exec` to enumerate the symbol table."
                ),
                pyghidra_hint=(
                    f"[s.getName() for s in sm.getSymbols() if {address!r} in str(s.getName())][:10]"
                ),
                field="name",
                requested=str(address),
            )

        if reason == "unanalyzed_code":
            next_action = (
                "address is code but Ghidra hasn't analysed it. Try "
                "`pyghidra.exec` with `flatAPI.disassemble(toAddr(<addr>))` or "
                "`flatAPI.createFunction(toAddr(<addr>), None)`."
            )
            pyghidra_hint = (
                f"flatAPI.disassemble(toAddr({address!r})); "
                f"flatAPI.createFunction(toAddr({address!r}), None)"
            )
        elif reason == "plt_thunk_unresolved":
            next_action = (
                "address is in a PLT block but the GOT target couldn't be "
                "resolved. Use `pyghidra.exec` to inspect the relocation directly."
            )
            pyghidra_hint = (
                f"list(currentProgram.getReferenceManager().getReferencesFrom(toAddr({address!r})))"
            )
        elif reason == "data":
            next_action = (
                "address is in a data section. Use `pyghidra.exec` with "
                "`flatAPI.getBytes(toAddr(<addr>), N)` to read raw bytes."
            )
            pyghidra_hint = f"flatAPI.getBytes(toAddr({address!r}), 16).tolist()"
        else:
            # When the agent passes a tiny address that's clearly below any
            # plausible image base, that's almost always a PIE-offset they
            # forgot to add the base to. Suggest the fix directly.
            try:
                raw_int = int(str(address), 16 if "x" in str(address).lower() else 10)
            except ValueError:
                raw_int = -1
            if 0 <= raw_int < 0x100000:
                next_action = (
                    f"address {address!r} is too small to be a real virtual "
                    "address in this PIE binary -- you likely have a file-relative "
                    "offset. Call `binary.summary` to see the image_base and add "
                    "it (e.g. 0x100000) to your address before retrying."
                )
            else:
                next_action = (
                    "address isn't in any code section. Check `binary.summary` for "
                    "valid section ranges, or use `pyghidra.exec` for low-level access."
                )
            pyghidra_hint = f"currentProgram.getMemory().getBlock(toAddr({address!r}))"

        raise ToolError(
            message,
            error_code="not_found_address",
            next_action=next_action,
            pyghidra_hint=pyghidra_hint,
            field="address",
            in_section=in_section,
            is_code=is_code,
            reason=reason,
            nearest_function=result.get("nearest_function"),
            requested=str(address),
        )

    raise ToolError(
        f"address-tolerance pipeline returned unknown kind: {kind!r}",
        error_code="internal",
    )
