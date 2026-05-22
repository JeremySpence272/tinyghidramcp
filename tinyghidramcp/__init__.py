"""tinyghidramcp: minimal Ghidra MCP server for AI agents."""

from ._version import __version__
from .backend import GhidraBackend, GhidraBackendError
from .server import JsonRpcError, SimpleMcpServer

__all__ = [
    "GhidraBackend",
    "GhidraBackendError",
    "JsonRpcError",
    "SimpleMcpServer",
    "__version__",
]
