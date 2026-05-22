"""CLI runner for the tinyghidramcp server."""

from __future__ import annotations

import argparse
import os
import sys
from types import ModuleType

from ._version import __version__
from .backend import GhidraBackend
from .server import SimpleMcpServer
from .telemetry import from_env as telemetry_from_env


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="tinyghidramcp server (stdio MCP)")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def load_pyghidra_module() -> ModuleType:
    try:
        import pyghidra  # pylint: disable=import-outside-toplevel
    except ImportError as exc:  # pragma: no cover - depends on system environment
        raise RuntimeError("pyghidra is not available. Install it.") from exc
    return pyghidra


def resolve_install_dir() -> str:
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        return install_dir
    raise RuntimeError("GHIDRA_INSTALL_DIR is required. Set it in the environment.")


def build_backend() -> GhidraBackend:
    install_dir = resolve_install_dir()
    pyghidra_module = load_pyghidra_module()
    return GhidraBackend(pyghidra_module, install_dir=install_dir, deterministic=True)


def _ghidra_version_from_install_dir() -> str | None:
    """Best-effort read of Ghidra version from $GHIDRA_INSTALL_DIR."""
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir:
        return None
    props = os.path.join(install_dir, "Ghidra", "application.properties")
    if not os.path.isfile(props):
        return None
    try:
        with open(props, encoding="utf-8") as f:
            for line in f:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def _git_sha_at_runtime() -> str | None:
    """Return the source git SHA if available.

    Order: build-time-baked value in ``_build_info.GIT_SHA``, then a
    subprocess ``git rev-parse HEAD`` from the package directory. Returns
    None if neither works (production install with git stripped).
    """
    try:
        from . import _build_info
        if _build_info.GIT_SHA:
            return _build_info.GIT_SHA
    except ImportError:
        pass

    import subprocess
    from pathlib import Path

    pkg_dir = Path(__file__).resolve().parent.parent
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=pkg_dir, capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            sha = out.stdout.strip()
            return sha or None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)

    telemetry = telemetry_from_env()
    backend = build_backend()
    server = SimpleMcpServer(backend, telemetry=telemetry)

    # Every session file starts with exactly one `session_start` record.
    # `bootstrap_status` distinguishes success ("ok") from failure ("failed")
    # so the analyzer can read the first line and know which path was taken.
    bootstrap_error: str | None = None
    try:
        server.bootstrap_program()
    except Exception as exc:
        bootstrap_error = str(exc)

    telemetry.emit_session_start(
        ghidra_version=_ghidra_version_from_install_dir(),
        git_sha=_git_sha_at_runtime(),
        binary_path=SimpleMcpServer.BINARY_PATH,
        bootstrap_status="ok" if bootstrap_error is None else "failed",
        bootstrap_error=bootstrap_error,
    )

    if bootstrap_error is not None:
        telemetry.close()
        print(f"tinyghidramcp: failed to open warmed project: {bootstrap_error}", file=sys.stderr)
        return 2

    try:
        server.serve_stdio()
    finally:
        telemetry.close()
    return 0
