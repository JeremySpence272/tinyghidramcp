"""CLI runner for the tinyghidramcp server."""

from __future__ import annotations

import argparse
import os
from types import ModuleType

from ._version import __version__
from .backend import GhidraBackend
from .server import SimpleMcpServer


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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    backend = build_backend()
    server = SimpleMcpServer(backend)
    server.serve_stdio()
    return 0
