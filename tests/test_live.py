"""Live tests against a real Ghidra 12.1 install.

These tests are skipped unless:

  1. ``GHIDRA_INSTALL_DIR`` is set and the install actually exists.
  2. The ``pyghidra`` package imports cleanly.
  3. A warmed Ghidra project exists at ``/var/lib/tinyghidramcp/project/``
     (or ``TINYGHIDRAMCP_TEST_PROJECT_DIR`` if set, for dev runs).

To bootstrap a test project locally::

    $GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/tgm-test-project tgm \
        -import /bin/ls -overwrite

then::

    TINYGHIDRAMCP_TEST_PROJECT_DIR=/tmp/tgm-test-project \
        pytest -m live tests/test_live.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.live


def _have_ghidra() -> bool:
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir or not Path(install_dir).is_dir():
        return False
    try:
        import pyghidra  # noqa: F401
    except ImportError:
        return False
    project_dir = os.environ.get(
        "TINYGHIDRAMCP_TEST_PROJECT_DIR", "/var/lib/tinyghidramcp/project"
    )
    return Path(project_dir).is_dir()


if not _have_ghidra():
    pytest.skip(
        "live tests need GHIDRA_INSTALL_DIR + pyghidra + a warmed project",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def live_server():
    from tinyghidramcp.backend import GhidraBackend
    from tinyghidramcp.server import SimpleMcpServer

    project_dir = os.environ.get(
        "TINYGHIDRAMCP_TEST_PROJECT_DIR", "/var/lib/tinyghidramcp/project"
    )
    install_dir = os.environ["GHIDRA_INSTALL_DIR"]

    import pyghidra

    backend = GhidraBackend(pyghidra, install_dir=install_dir, deterministic=True)
    server = SimpleMcpServer(backend)
    # Override the hardcoded project dir for the test if needed.
    server.WARMED_PROJECT_DIR = project_dir
    server.bootstrap_program()
    yield server


def test_live_binary_summary_returns_curated_payload(live_server):
    handler = live_server._tool_handlers["binary.summary"]
    payload = handler({})
    # Every curated field must be present.
    for key in ("filename", "language_id", "entry_point", "sections",
                "security", "language_hint", "top_symbols"):
        assert key in payload, f"binary.summary missing {key}"
    assert payload["sections"], "expected at least one section"
    assert isinstance(payload["security"], dict)
    assert payload["language_hint"] in {"c", "c++", "go", "rust"}


def test_live_decompile_main_or_entry(live_server):
    """Decompile *something* from this binary. Try `main` first, then the entry
    point, then top symbols, then any function manager entry."""
    handler = live_server._tool_handlers["decompile"]
    summary = live_server._tool_handlers["binary.summary"]({})

    candidates = ["main"]
    if summary.get("entry_point"):
        candidates.append(summary["entry_point"])
    for sym in summary.get("top_symbols", [])[:5]:
        if sym.get("address"):
            candidates.append(sym["address"])

    last_exc = None
    for candidate in candidates:
        try:
            payload = handler({"target": candidate})
            assert isinstance(payload, dict)
            assert "cached" in payload  # confirms the decompile cache wrapped the call
            return  # one success is enough
        except Exception as e:
            last_exc = e
    raise AssertionError(
        f"no candidate decompiled cleanly; last error: {last_exc!r}; "
        f"tried: {candidates}"
    )


def test_live_tools_list_returns_twelve(live_server):
    res = live_server._dispatch_tools_list({})
    assert res["total"] == 12
