"""Persistent global state for ``pyghidra.exec`` calls within one session.

The upstream ``GhidraBackend.eval_code`` creates a fresh context per call. To
satisfy the design promise that **globals persist across pyghidra.exec calls in
a session**, the server-side handler wraps the agent's code with prelude /
postlude that round-trip state through this module's ``STATE`` dict.

Bound names (per the v2 plan):
  currentProgram, currentAddress, monitor, flatAPI, decompAPI,
  listing, fm, sm, mem, cache (with cache.invalidate())
"""

from __future__ import annotations

import sys
from typing import Any

# Persistent globals dict shared across pyghidra.exec calls. Module-level so it
# survives multiple invocations; reset only when the server process restarts.
STATE: dict[str, Any] = {}

# Backend-injected names that should NEVER be persisted (they're refreshed each
# call from the live backend session).
_BACKEND_KEYS: set[str] = {
    "pyghidra", "ghidra", "java", "sessions", "session_id", "program",
    "project", "ghidra_project", "flat_api", "decompiler", "listing",
    "memory", "symbol_table",
    # Our injected aliases (also refreshed each call).
    "currentProgram", "currentAddress", "monitor", "flatAPI", "decompAPI",
    "fm", "sm", "mem", "cache",
}

# Sticky address (lives in STATE but is exposed as `currentAddress`).
_CURRENT_ADDRESS_KEY = "_tgm_current_address"

# Set by `_TGMCache.invalidate()`; the server reads + clears it after each call.
INVALIDATE_REQUESTED: bool = False


class _TGMCache:
    """Object bound as `cache` in pyghidra.exec. Single method: invalidate()."""

    @staticmethod
    def invalidate() -> None:
        """Request decompile-cache flush after this script returns."""
        global INVALIDATE_REQUESTED
        INVALIDATE_REQUESTED = True


def inject(ns: dict[str, Any]) -> None:
    """Inject persisted state + bound aliases into the eval namespace.

    Called from the prelude that the server prepends to every agent script.
    ``ns`` is the eval context (which contains the backend-supplied
    ``program``, ``flat_api``, ``decompiler``, ``listing``, ``memory``,
    ``symbol_table`` keys).
    """
    # 1) Layer in persisted state first so agent's previous globals are visible.
    ns.update(STATE)

    # 2) Set up aliases from the backend-supplied names. These overwrite any
    #    same-named keys in STATE (they're live each call).
    program = ns.get("program")
    if program is not None:
        ns["currentProgram"] = program
        ns["fm"] = program.getFunctionManager()
        ns["sm"] = program.getSymbolTable()
        ns["mem"] = program.getMemory()
    ns["listing"] = ns.get("listing") or (program.getListing() if program is not None else None)
    ns["flatAPI"] = ns.get("flat_api")
    ns["decompAPI"] = ns.get("decompiler")
    # Sticky currentAddress: persists across calls in STATE.
    ns["currentAddress"] = STATE.get(_CURRENT_ADDRESS_KEY)
    ns["monitor"] = ns.get("monitor")  # left None in headless mode
    ns["cache"] = _TGMCache()


def persist(ns: dict[str, Any]) -> int:
    """Save agent-created globals from ``ns`` back into STATE.

    Returns the rough byte size of STATE after persistence (telemetry signal).
    Skips dunder names, backend-supplied keys, and our injected aliases.
    """
    for k, v in list(ns.items()):
        if k.startswith("_"):
            continue
        if k in _BACKEND_KEYS:
            continue
        STATE[k] = v
    # Sticky currentAddress: capture if the agent reassigned it.
    if "currentAddress" in ns and ns["currentAddress"] is not None:
        STATE[_CURRENT_ADDRESS_KEY] = ns["currentAddress"]
    return _approx_size(STATE)


def _approx_size(d: dict[str, Any]) -> int:
    """Best-effort size estimate. Not exact; just a telemetry hint."""
    total = sys.getsizeof(d)
    for k, v in d.items():
        try:
            total += sys.getsizeof(k) + sys.getsizeof(v)
        except Exception:
            pass
    return total


def pop_invalidate_request() -> bool:
    """Read-and-clear the cache-invalidation flag."""
    global INVALIDATE_REQUESTED
    flag = INVALIDATE_REQUESTED
    INVALIDATE_REQUESTED = False
    return flag


def reset() -> None:
    """Test helper: clear persisted state."""
    STATE.clear()
    global INVALIDATE_REQUESTED
    INVALIDATE_REQUESTED = False


def snapshot() -> dict[str, Any]:
    """Capture pre-call STATE + invalidate flag so a timed-out / failed script
    can be rolled back to last-known-good. Shallow dict copy: the *keys* are
    snapshotted, and Python objects held by STATE are referenced by identity
    (deep-copying live Ghidra Java handles isn't safe)."""
    return {
        "state": dict(STATE),  # shallow copy of the dict itself
        "invalidate": INVALIDATE_REQUESTED,
    }


def restore(snap: dict[str, Any]) -> None:
    """Roll back STATE and the invalidate flag to a previous snapshot."""
    global INVALIDATE_REQUESTED
    STATE.clear()
    STATE.update(snap.get("state", {}))
    INVALIDATE_REQUESTED = bool(snap.get("invalidate", False))
