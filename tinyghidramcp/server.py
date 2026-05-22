"""Minimal MCP (JSON-RPC) server with Ghidra-backed tools."""

from __future__ import annotations

import inspect
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, BinaryIO

from ._version import __version__
from .address_tolerance import resolve as _resolve_address
from .backend import GhidraBackend, GhidraBackendError
from .errors import ToolError, build_error_payload

# Hard ceiling on decompile output. Agents can lower via the per-call arg; this
# is the upper bound applied even when no arg is given.
DECOMPILE_HARD_CEILING_LINES = 4000
DECOMPILE_DEFAULT_LINES = 800


def _apply_max_lines(payload: dict, max_lines: int | None) -> dict:
    """Truncate the `decompiled` / `result` text in a decompile payload.

    Looks at common upstream keys (``decompiled``, ``decompile_of``, ``result``)
    and clips to ``max_lines`` lines. ``max_lines=None`` falls back to the
    default; the hard ceiling always applies.
    """
    if not isinstance(payload, dict):
        return payload
    cap = max_lines or DECOMPILE_DEFAULT_LINES
    cap = min(cap, DECOMPILE_HARD_CEILING_LINES)
    for key in ("decompiled", "decompile", "c_code", "result"):
        value = payload.get(key)
        if isinstance(value, str) and "\n" in value:
            lines = value.split("\n")
            if len(lines) > cap:
                payload[key] = "\n".join(lines[:cap])
                payload["truncated_lines"] = len(lines) - cap
                payload["max_lines_applied"] = cap
    return payload

_ADDRESS_SCHEMA: dict[str, Any] = {
    "oneOf": [{"type": "integer"}, {"type": "string"}],
}

_PYGHIDRA_CTA = (
    " If your use case isn't covered by the available named tools, drop to "
    "`pyghidra.exec` for full Ghidra Python API access."
)

_SERVER_TOOL_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "meta.help",
        "description": (
            "Return long-form documentation, parameters, examples, and a `pyghidra.exec` "
            "alternative for a named tool." + _PYGHIDRA_CTA
        ),
        "properties": {"tool": {"type": "string"}},
        "required": ["tool"],
        "backend_method": None,
    },
    {
        "name": "decompile.batch",
        "description": (
            "Decompile many functions in one call. Returns a dict keyed by the input target "
            "string (whatever the agent passed for each target). Order irrelevant." + _PYGHIDRA_CTA
        ),
        "properties": {
            "targets": {"type": "array", "items": {"type": "string"}},
            "max_lines_each": {"type": "integer"},
        },
        "required": ["targets"],
        "backend_method": None,
    },
)

# Backend-method -> MCP tool name. Phase 1c minimal surface: 10 tools that map to
# existing backend methods. The two server-level tools (`meta.help`, `decompile.batch`)
# live in _SERVER_TOOL_SPECS. Phase 2 will refactor these methods to drop the
# session_id argument (one program per session) and add the address-tolerance layer.
_BACKEND_TOOL_NAME_MAP: dict[str, str] = {
    "binary_summary":   "binary.summary",
    "function_by_name": "search.functions",
    "binary_strings":   "search.strings",
    "decomp_function":  "decompile",
    "disasm_function":  "disassemble",
    "xref_to":          "xrefs.to",
    "xref_from":        "xrefs.from",
    "callgraph_paths":  "callgraph",
    "address_resolve":  "resolve",
    "eval_code":        "pyghidra.exec",
}

# Tool descriptions. All named-tool descriptions end with the pyghidra CTA so
# agents are reminded of the escape hatch every time they read tools/list.
_DESCRIPTION_OVERRIDES: dict[str, str] = {
    "binary.summary": (
        "Return the open program's architecture, endianness, image base, entry, sections, "
        "dynamic deps, security flags (RELRO/NX/PIE/canary/stripped), runtime/language hint, "
        "and top symbols sorted by xref count." + _PYGHIDRA_CTA
    ),
    "search.functions": (
        "Search functions by name (regex). Returns name, entry address, signature." + _PYGHIDRA_CTA
    ),
    "search.strings": (
        "Search defined strings by content. Supports min-length filter and encoding." + _PYGHIDRA_CTA
    ),
    "decompile": (
        "Decompile one function. `target` is a hex address or symbol name; the server "
        "auto-detects and applies address tolerance (mid-function, PLT, unanalysed)." + _PYGHIDRA_CTA
    ),
    "decompile.batch": (
        "Decompile many functions in one call. Returns a dict keyed by the input target." + _PYGHIDRA_CTA
    ),
    "disassemble": (
        "Disassemble a function or address range. Lines include absolute addresses and "
        "demangled symbols." + _PYGHIDRA_CTA
    ),
    "xrefs.to": (
        "Find code references TO an address. Set include_data=true for data refs too." + _PYGHIDRA_CTA
    ),
    "xrefs.from": (
        "Find code references FROM an address. Set include_data=true for data refs too." + _PYGHIDRA_CTA
    ),
    "callgraph": (
        "Bounded call-graph traversal. Returns flat edge list (caller, callee, callsite)." + _PYGHIDRA_CTA
    ),
    "resolve": (
        "Resolve a symbol name or expression into one or more candidate addresses." + _PYGHIDRA_CTA
    ),
    "pyghidra.exec": (
        "Run arbitrary Python with currentProgram, currentAddress, monitor, flatAPI, "
        "decompAPI, listing, fm, sm, mem, and cache bound. Globals persist between calls. "
        "No sandbox. This runs as root in the agent's container with full filesystem and "
        "Ghidra API access."
    ),
    "meta.help": (
        "Return long-form documentation for a named tool, with parameter descriptions, "
        "example invocations, and a copy-pasteable pyghidra.exec alternative." + _PYGHIDRA_CTA
    ),
}

_ADDRESS_PARAM_NAMES = {
    "address",
    "start",
    "end",
    "function_start",
    "callsite",
    "from_address",
    "to_address",
    "external_address",
    "base_address",
    "image_base",
    "source_function",
    "target_function",
    "symbol_address",
    "storage_address",
    "thunk_target",
}


def _tool_name_map() -> dict[str, str]:
    return dict(_BACKEND_TOOL_NAME_MAP)


def _tool_description(tool_name: str) -> str:
    if tool_name in _DESCRIPTION_OVERRIDES:
        return _DESCRIPTION_OVERRIDES[tool_name]
    return tool_name.replace(".", " ").replace("_", " ") + "."


def _tool_property_schema(param_name: str, param: inspect.Parameter) -> dict[str, Any]:
    if param_name in _ADDRESS_PARAM_NAMES:
        return dict(_ADDRESS_SCHEMA)
    annotation = "" if param.annotation is inspect._empty else str(param.annotation)
    default = param.default
    if param_name == "args":
        return {"type": "array", "items": {}}
    if param_name == "script_args":
        return {"type": "array", "items": {"type": "string"}}
    if param_name == "values":
        return {"type": "array", "items": {"type": "integer"}}
    if param_name == "kwargs":
        return {"type": "object"}
    if isinstance(default, bool) or "bool" in annotation:
        return {"type": "boolean"}
    if isinstance(default, int) and not isinstance(default, bool):
        return {"type": "integer"}
    if isinstance(default, float):
        return {"type": "number"}
    if isinstance(default, str):
        return {"type": "string"}
    if isinstance(default, (list, tuple)):
        return {"type": "array", "items": {}}
    if isinstance(default, dict):
        return {"type": "object"}
    if "list" in annotation or "tuple" in annotation:
        return {"type": "array", "items": {}}
    if "dict" in annotation:
        return {"type": "object"}
    if "int" in annotation and "str" not in annotation:
        return {"type": "integer"}
    if "str" in annotation and "int" not in annotation:
        return {"type": "string"}
    if "int" in annotation and "str" in annotation:
        return dict(_ADDRESS_SCHEMA)
    return {}


def _backend_tool_spec(backend_method: str) -> dict[str, Any]:
    method = getattr(GhidraBackend, backend_method)
    signature = inspect.signature(method)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, param in signature.parameters.items():
        if name == "self":
            continue
        # session_id is injected by the server (one program per session); never
        # surfaced on the agent's tool input schema.
        if name == "session_id":
            continue
        properties[name] = _tool_property_schema(name, param)
        if param.default is inspect._empty:
            required.append(name)
    tool_name = _tool_name_map()[backend_method]
    return {
        "name": tool_name,
        "description": _tool_description(tool_name),
        "backend_method": backend_method,
        "properties": properties,
        "required": required,
    }


def _build_backend_tool_specs() -> tuple[dict[str, Any], ...]:
    """Build tool specs for every mapped backend method.

    Phase 1c contract: every name in _BACKEND_TOOL_NAME_MAP must correspond to an
    existing GhidraBackend method. Backend methods that are *not* mapped are
    silently ignored — this is the inverse of the upstream contract and lets us
    keep unused backend code around without surfacing it in tools/list.
    """
    mapping = _tool_name_map()
    backend_methods = {
        name
        for name, member in inspect.getmembers(GhidraBackend, inspect.isfunction)
        if not name.startswith("_") and name not in {"ping", "shutdown"}
    }
    dangling = sorted(set(mapping) - backend_methods)
    if dangling:
        raise RuntimeError(
            "tool name map references missing backend methods: " + ", ".join(dangling)
        )
    return tuple(
        _backend_tool_spec(backend_method)
        for backend_method in sorted(mapping, key=lambda item: mapping[item])
    )


def _augment_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Patch auto-generated specs where the custom handler accepts extra args."""
    if spec["name"] == "decompile":
        # Custom handler accepts max_lines on top of the upstream signature.
        spec["properties"]["max_lines"] = {"type": "integer"}
    return spec


BACKEND_TOOL_SPECS: tuple[dict[str, Any], ...] = tuple(
    _augment_spec(dict(spec, properties=dict(spec["properties"])))
    for spec in _build_backend_tool_specs()
)

ALL_TOOL_SPECS: tuple[dict[str, Any], ...] = _SERVER_TOOL_SPECS + BACKEND_TOOL_SPECS

_SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2025-03-26",
    "2024-11-05",
)
_DEFAULT_PROTOCOL_VERSION = _SUPPORTED_PROTOCOL_VERSIONS[0]


@dataclass
class JsonRpcError(Exception):
    """Represents a JSON-RPC error payload."""

    code: int
    message: str
    data: Any = None


class SimpleMcpServer:
    """Simple MCP-compatible server exposing Ghidra tools.

    Single-program-per-session model. On bootstrap, the server opens the warmed
    Ghidra project at WARMED_PROJECT_DIR (populated by revbench's warm-up step
    before the server is spawned) and stashes the resulting session_id. The
    session_id is then injected into every backend tool call; it never appears
    in the agent's input schema.
    """

    WARMED_PROJECT_DIR = "/var/lib/tinyghidramcp/project"
    WARMED_PROJECT_NAME = "tgm"
    BINARY_PATH = "/workspace/challenge/binary"

    def __init__(self, backend: Any, telemetry: Any = None):
        from .decompile_cache import DecompileCache
        from .telemetry import Telemetry, from_env

        self._backend = backend
        self._auto_session_id: str | None = None
        self._telemetry: Telemetry = telemetry if telemetry is not None else from_env()
        self._decompile_cache = DecompileCache()
        # Cached binary.summary response for the session; computed once on first call.
        self._binary_summary_cache: dict[str, Any] | None = None
        self._tool_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "meta.help": self._tool_meta_help,
            "decompile.batch": self._tool_decompile_batch,
        }
        for spec in BACKEND_TOOL_SPECS:
            if spec["name"] == "pyghidra.exec":
                # Custom wrapper: persistent globals, bound aliases, cache helper.
                self._tool_handlers[spec["name"]] = self._tool_pyghidra_exec
            elif spec["name"] == "decompile":
                # Custom wrapper: address tolerance + LRU cache.
                self._tool_handlers[spec["name"]] = self._tool_decompile
            elif spec["name"] == "binary.summary":
                # Custom wrapper: composes upstream + recon script into curated response.
                self._tool_handlers[spec["name"]] = self._tool_binary_summary
            else:
                self._tool_handlers[spec["name"]] = self._make_backend_handler(spec["backend_method"])

    def bootstrap_program(self) -> None:
        """Open the warmed Ghidra project and bind it as the implicit session.

        Called once at server startup by the CLI. Raises RuntimeError if the
        warmed project is missing or doesn't contain exactly one program.
        """
        import os

        if not os.path.isdir(self.WARMED_PROJECT_DIR):
            raise RuntimeError(
                f"warmed Ghidra project not found at {self.WARMED_PROJECT_DIR}. "
                "The warm-up step (analyzeHeadless) must run before the server starts."
            )
        # Ensure the JVM is up so we can call Ghidra API directly.
        self._backend._ensure_started()
        program_name = self._discover_only_program()
        result = self._backend.session_open_existing(
            self.WARMED_PROJECT_DIR,
            self.WARMED_PROJECT_NAME,
            program_name=program_name,
            read_only=True,
        )
        self._auto_session_id = result["session_id"]

    def _discover_only_program(self) -> str:
        from ghidra.base.project import GhidraProject  # type: ignore[import-not-found]

        project = GhidraProject.openProject(self.WARMED_PROJECT_DIR, self.WARMED_PROJECT_NAME)
        try:
            files = list(project.getRootFolder().getFiles())
            programs = [f for f in files if str(f.getContentType()) == "Program"]
            if not programs:
                raise RuntimeError(
                    f"no programs found in project at {self.WARMED_PROJECT_DIR}"
                )
            if len(programs) > 1:
                names = [str(f.getName()) for f in programs]
                raise RuntimeError(
                    f"expected exactly one program in project, found {len(programs)}: {names}"
                )
            return str(programs[0].getName())
        finally:
            project.close()

    def serve_stdio(
        self,
        input_stream: BinaryIO | None = None,
        output_stream: BinaryIO | None = None,
    ) -> None:
        """Run JSON-RPC over stdio, mirroring line or Content-Length framing."""

        in_stream = input_stream or sys.stdin.buffer
        out_stream = output_stream or sys.stdout.buffer

        while True:
            try:
                line, framing = self._read_stdio_request(in_stream)
            except JsonRpcError as exc:
                response = json.dumps(self._error_response(None, exc), sort_keys=True)
                self._write_stdio_response(out_stream, response)
                continue
            if line is None:
                return

            response = self.handle_json_line(line)
            if response is None:
                continue

            self._write_stdio_response(out_stream, response, framing=framing)

    def handle_json_line(self, line: str) -> str | None:
        """Handle one JSON-RPC line and return a serialized response line."""

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            self._telemetry.emit_pre_dispatch_error(
                error_code="json_parse_error",
                raw_args_preview=line,
                message=str(exc),
            )
            error = JsonRpcError(code=-32700, message="Parse error", data=str(exc))
            return json.dumps(self._error_response(None, error), sort_keys=True)

        response = self.handle_request(request)
        if response is None:
            return None
        try:
            return json.dumps(response, sort_keys=True)
        except TypeError as exc:
            request_id = request.get("id") if isinstance(request, dict) else None
            fallback = self._error_response(
                request_id,
                JsonRpcError(
                    code=-32603,
                    message="Internal error",
                    data=f"failed to serialize response: {exc}",
                ),
            )
            return json.dumps(fallback, sort_keys=True)

    @staticmethod
    def _read_stdio_request(stream: BinaryIO) -> tuple[str | None, str]:
        """Read one stdio request, preferring MCP framing and tolerating JSON lines."""

        while True:
            raw_line = stream.readline()
            if not raw_line:
                return None, "line"
            if raw_line in (b"\r\n", b"\n"):
                continue

            stripped = raw_line.strip()
            if stripped.startswith((b"{", b"[")):
                try:
                    return stripped.decode("utf-8"), "line"
                except UnicodeDecodeError as exc:
                    raise JsonRpcError(
                        code=-32700,
                        message="Parse error",
                        data=f"invalid UTF-8 request line: {exc}",
                    ) from exc

            header_lines = [raw_line]
            break

        while True:
            raw_line = stream.readline()
            if not raw_line:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data="unexpected EOF while reading stdio headers",
                )
            if raw_line in (b"\r\n", b"\n"):
                break
            header_lines.append(raw_line)

        content_length: int | None = None
        for raw_header in header_lines:
            try:
                header = raw_header.decode("ascii").strip()
            except UnicodeDecodeError as exc:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data=f"invalid stdio header encoding: {exc}",
                ) from exc
            name, sep, value = header.partition(":")
            if not sep:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data=f"invalid stdio header: {header}",
                )
            if name.lower() != "content-length":
                continue
            try:
                content_length = int(value.strip())
            except ValueError as exc:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data=f"invalid Content-Length header: {header}",
                ) from exc

        if content_length is None:
            raise JsonRpcError(
                code=-32700,
                message="Parse error",
                data="missing Content-Length header",
            )

        body = stream.read(content_length)
        if len(body) != content_length:
            raise JsonRpcError(
                code=-32700,
                message="Parse error",
                data="unexpected EOF while reading stdio body",
            )
        try:
            return body.decode("utf-8"), "content-length"
        except UnicodeDecodeError as exc:
            raise JsonRpcError(
                code=-32700,
                message="Parse error",
                data=f"invalid UTF-8 request body: {exc}",
            ) from exc

    @staticmethod
    def _write_stdio_response(
        stream: BinaryIO,
        response: str,
        *,
        framing: str = "line",
    ) -> None:
        body = response.encode("utf-8")
        if framing == "content-length":
            header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            stream.write(header)
        stream.write(body)
        if framing != "content-length":
            stream.write(b"\n")
        stream.flush()

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC request object."""

        if not isinstance(request, dict):
            return self._error_response(None, JsonRpcError(-32600, "Invalid Request"))

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        try:
            if not isinstance(method, str):
                raise JsonRpcError(-32600, "Invalid Request")
            if not isinstance(params, dict):
                raise JsonRpcError(-32602, "Invalid params")

            if method == "notifications/initialized":
                return None

            result = self._dispatch(method, params)
            return self._success_response(request_id, result)
        except JsonRpcError as exc:
            return self._error_response(request_id, exc)
        except Exception as exc:
            return self._error_response(
                request_id,
                JsonRpcError(
                    code=-32603,
                    message="Internal error",
                    data=f"{type(exc).__name__}: {exc}",
                ),
            )

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": self._negotiate_protocol_version(params),
                "serverInfo": {
                    "name": "tinyghidramcp",
                    "version": __version__,
                },
                "capabilities": {
                    "tools": {},
                },
            }

        if method == "ping":
            return {"status": "ok"}

        if method == "tools/list":
            return self._dispatch_tools_list(params)

        if method == "tools/call":
            return self._dispatch_tool_call(params)

        if method == "shutdown":
            self._backend.shutdown()
            return {"ok": True}

        raise JsonRpcError(code=-32601, message=f"Method not found: {method}")

    @staticmethod
    def _negotiate_protocol_version(params: dict[str, Any]) -> str:
        requested = params.get("protocolVersion")
        if requested is None:
            return _DEFAULT_PROTOCOL_VERSION
        if not isinstance(requested, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: initialize 'protocolVersion' must be a string",
            )
        if requested in _SUPPORTED_PROTOCOL_VERSIONS:
            return requested
        return _DEFAULT_PROTOCOL_VERSION

    def _dispatch_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        paginate = "offset" in params or "limit" in params
        offset = params.get("offset", 0)
        limit = params.get("limit", 50 if paginate else None)
        prefix = params.get("prefix")
        query = params.get("query")

        if not isinstance(offset, int):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'offset' must be an integer",
            )
        if limit is not None and not isinstance(limit, int):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'limit' must be an integer",
            )
        if offset < 0:
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'offset' must be >= 0",
            )
        if limit is not None and limit <= 0:
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'limit' must be > 0",
            )
        if prefix is not None and not isinstance(prefix, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'prefix' must be a string",
            )
        if query is not None and not isinstance(query, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'query' must be a string",
            )

        tools = self._tool_definitions()
        if prefix is not None:
            tools = [tool for tool in tools if tool["name"].startswith(prefix)]
        if query is not None:
            lowered = query.lower()
            tools = [
                tool
                for tool in tools
                if lowered in tool["name"].lower() or lowered in tool["description"].lower()
            ]

        total = len(tools)
        if limit is None:
            items = tools[offset:]
            effective_limit = len(items)
        else:
            items = tools[offset : offset + limit]
            effective_limit = limit

        has_more = offset + len(items) < total
        response = {
            "tools": items,
            "offset": offset,
            "limit": effective_limit,
            "total": total,
            "has_more": has_more,
        }
        if has_more:
            response["next_offset"] = offset + len(items)
            response["notice"] = (
                "tool list is truncated; request the next page via tools/list with "
                f"offset={response['next_offset']}"
            )
        return response

    def _dispatch_tool_call(self, params: dict[str, Any]) -> dict[str, Any]:
        import time

        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str):
            self._telemetry.emit_pre_dispatch_error(
                error_code="validation_error",
                validation_field="name",
                validation_expected="string",
                message="tools/call requires 'name'",
            )
            raise JsonRpcError(code=-32602, message="Invalid params: tools/call requires 'name'")
        if not isinstance(arguments, dict):
            self._telemetry.emit_pre_dispatch_error(
                error_code="validation_error",
                tool=name,
                validation_field="arguments",
                validation_expected="object",
                message="tools/call 'arguments' must be an object",
            )
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/call 'arguments' must be an object",
            )

        handler = self._tool_handlers.get(name)
        if handler is None:
            self._telemetry.emit_pre_dispatch_error(
                error_code="tool_not_found",
                requested_tool=name,
            )
            raise JsonRpcError(code=-32601, message=f"Tool not found: {name}")

        t0 = time.monotonic()
        try:
            payload = handler(arguments)
            result = self._tool_result(payload)
            self._emit_call_telemetry(
                tool=name,
                arguments=arguments,
                status="ok",
                error_code=None,
                latency_ms=int((time.monotonic() - t0) * 1000),
                payload=payload,
                is_error=False,
            )
            return result
        except GhidraBackendError as exc:
            payload = build_error_payload(exc)
            self._emit_call_telemetry(
                tool=name,
                arguments=arguments,
                status="error",
                error_code=payload.get("error_code", "internal"),
                latency_ms=int((time.monotonic() - t0) * 1000),
                payload=payload,
                is_error=True,
            )
            return self._tool_result(payload, is_error=True)
        except Exception as exc:  # pragma: no cover - safety net
            payload = {
                "error": f"unexpected tool failure: {type(exc).__name__}: {exc}",
                "error_code": "internal",
            }
            self._emit_call_telemetry(
                tool=name,
                arguments=arguments,
                status="error",
                error_code="internal",
                latency_ms=int((time.monotonic() - t0) * 1000),
                payload=payload,
                is_error=True,
            )
            return self._tool_result(
                payload,
                is_error=True,
            )

    def _emit_call_telemetry(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        status: str,
        error_code: str | None,
        latency_ms: int,
        payload: dict[str, Any],
        is_error: bool,
    ) -> None:
        """Emit one telemetry record per tool_call dispatch."""
        # Serialize payload to measure result_size_bytes; reuse for preview.
        try:
            payload_text = json.dumps(payload, default=str)
        except Exception:
            payload_text = repr(payload)
        # pyghidra.exec captures the full code body verbatim.
        code = arguments.get("code") if tool == "pyghidra.exec" else None
        # Address-tolerance metadata (phase 2c may inject this on the payload).
        address_adjusted = payload.get("address_adjusted") if isinstance(payload, dict) else None
        globals_size_bytes = (
            payload.get("globals_size_bytes")
            if tool == "pyghidra.exec" and isinstance(payload, dict)
            else None
        )
        self._telemetry.emit_tool_call(
            tool=tool,
            args=arguments,
            status=status,
            error_code=error_code,
            latency_ms=latency_ms,
            result_size_bytes=len(payload_text),
            result_preview=payload_text,
            cached=bool(payload.get("cached")) if isinstance(payload, dict) else False,
            address_adjusted=address_adjusted,
            code=code,
            globals_size_bytes=globals_size_bytes,
        )

    def _make_backend_handler(self, method_name: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
        backend_method = getattr(self._backend, method_name)
        # bind_signature is the bound-method signature (no `self`), used to bind args.
        bind_signature = inspect.signature(backend_method)
        # class_signature is the canonical signature from the class; we use it to
        # detect which params accept addresses regardless of whether the instance
        # is a real GhidraBackend or a test stub with a loose signature.
        class_signature = inspect.signature(getattr(GhidraBackend, method_name))
        accepts_session_id = "session_id" in class_signature.parameters
        # Address-tolerance is only useful where the call requires a function
        # entry (decompile, disassemble). xrefs.to / xrefs.from accept any
        # address (including data labels), so tolerance there would wrongly
        # reject legitimate string/data targets.
        _TOLERANT_METHODS = {"decomp_function", "disasm_function"}
        if method_name in _TOLERANT_METHODS:
            tolerant_params = [
                p for p in class_signature.parameters
                if p in ("address", "function_start")
            ]
        else:
            tolerant_params = []

        def handler(arguments: dict[str, Any]) -> dict[str, Any]:
            if accepts_session_id and self._auto_session_id is not None:
                arguments = {**arguments, "session_id": self._auto_session_id}

            address_adjusted: dict[str, Any] | None = None
            for param_name in tolerant_params:
                raw = arguments.get(param_name)
                if raw is None or raw == "":
                    continue
                if self._auto_session_id is None:
                    break  # no session, no tolerance pipeline
                hit = _resolve_address(self._backend, self._auto_session_id, raw)
                resolved = hit.get("address")
                if resolved and str(resolved).lower() != str(raw).lower():
                    address_adjusted = {
                        "requested": str(raw),
                        "resolved": resolved,
                        "reason": hit.get("reason", hit.get("kind")),
                    }
                    if hit.get("via"):
                        address_adjusted["via"] = hit["via"]
                    arguments = {**arguments, param_name: resolved}

            try:
                bound = bind_signature.bind(**arguments)
            except TypeError as exc:
                raise ToolError(
                    str(exc), error_code="bad_args", field=None, expected=None
                ) from exc
            result = backend_method(*bound.args, **bound.kwargs)
            if address_adjusted is not None and isinstance(result, dict):
                result["address_adjusted"] = address_adjusted
            return result

        return handler

    def _tool_meta_help(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Return hand-written long-form help for a named tool."""
        from . import meta

        name = arguments.get("tool")
        if not isinstance(name, str) or not name:
            raise ToolError(
                "meta.help requires a 'tool' string argument",
                error_code="bad_args",
                field="tool",
                expected="string",
            )
        entry = meta.get(name)
        if entry is None:
            raise ToolError(
                f"unknown tool: {name}",
                error_code="not_found_name",
                field="tool",
                next_action="call tools/list to see the 12 available tool names",
            )
        # Surface the entry verbatim plus the live schema for the agent's reference.
        spec = next((s for s in ALL_TOOL_SPECS if s.get("name") == name), None)
        return {
            "tool": name,
            "description": entry["description"],
            "parameters": entry["parameters"],
            "examples": entry["examples"],
            "pyghidra_alternative": entry["pyghidra_alternative"],
            "schema": spec.get("properties", {}) if spec else {},
            "required": spec.get("required", []) if spec else [],
        }

    # ---------- binary.summary --------------------------------------------

    def _tool_binary_summary(self, _arguments: dict[str, Any]) -> dict[str, Any]:
        """Composed binary.summary: upstream metadata + recon script output.

        Cached for the session lifetime (one binary per session; no LRU needed).
        """
        from . import binary_summary as bs

        if self._binary_summary_cache is not None:
            cached = dict(self._binary_summary_cache)
            cached["cached"] = True
            return cached
        upstream = self._backend.binary_summary(self._auto_session_id)
        raw_recon = self._backend.eval_code(
            bs.build_recon_script(), session_id=self._auto_session_id
        )
        recon = raw_recon.get("result") if isinstance(raw_recon, dict) else raw_recon
        if not isinstance(recon, dict):
            recon = {}
        curated = bs.curate(upstream if isinstance(upstream, dict) else {}, recon)
        self._binary_summary_cache = curated
        out = dict(curated)
        out["cached"] = False
        return out

    # ---------- decompile + decompile.batch -------------------------------

    def _tool_decompile(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Decompile one function with address tolerance + LRU cache."""
        target = arguments.get("function_start")
        if target is None or target == "":
            raise ToolError(
                "decompile requires a `function_start` argument",
                error_code="bad_args",
                field="function_start",
                expected="hex address or symbol name",
            )
        timeout_secs = arguments.get("timeout_secs", 30)
        max_lines = arguments.get("max_lines")
        if max_lines is not None and (not isinstance(max_lines, int) or max_lines <= 0):
            raise ToolError(
                "max_lines must be a positive integer",
                error_code="bad_args",
                field="max_lines",
                expected="positive integer",
            )
        return self._decompile_one(target, timeout_secs=timeout_secs, max_lines=max_lines)

    def _decompile_one(
        self, target: Any, *, timeout_secs: int, max_lines: int | None = None
    ) -> dict[str, Any]:
        """Shared resolver+cache+backend path for `decompile` and `decompile.batch`.

        ``max_lines`` truncates the returned decompile text (applied after the
        backend call; cached payload remains full-fidelity).
        """
        target_str = str(target)
        hit = _resolve_address(self._backend, self._auto_session_id, target)
        resolved = hit.get("address", target_str)
        address_adjusted = None
        if str(resolved).lower() != target_str.lower():
            address_adjusted = {
                "requested": target_str,
                "resolved": resolved,
                "reason": hit.get("reason", hit.get("kind")),
            }
            if hit.get("via"):
                address_adjusted["via"] = hit["via"]

        # Cache key: canonical resolved address + timeout. (max_lines truncates
        # post-cache so the cache stays compatible across different line caps.)
        cache_key = (resolved, timeout_secs)
        cached_value = self._decompile_cache.get(cache_key)
        if cached_value is not None:
            response = dict(cached_value)
            response["cached"] = True
            if address_adjusted is not None:
                response["address_adjusted"] = address_adjusted
            return _apply_max_lines(response, max_lines)

        raw = self._backend.decomp_function(
            self._auto_session_id, resolved, timeout_secs=timeout_secs
        )
        if not isinstance(raw, dict):
            return _apply_max_lines({"result": raw, "cached": False}, max_lines)
        # Store the *cacheable* part (drop per-call fields like address_adjusted).
        cacheable = {k: v for k, v in raw.items() if k != "address_adjusted"}
        self._decompile_cache.put(cache_key, cacheable)
        raw["cached"] = False
        if address_adjusted is not None:
            raw["address_adjusted"] = address_adjusted
        return _apply_max_lines(raw, max_lines)

    def _tool_decompile_batch(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Decompile many functions; return a dict keyed by the input target."""
        targets = arguments.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ToolError(
                "decompile.batch requires a non-empty `targets` list",
                error_code="bad_args",
                field="targets",
                expected="non-empty array of strings",
            )
        max_lines_each = arguments.get("max_lines_each", 200)
        if not isinstance(max_lines_each, int) or max_lines_each <= 0:
            raise ToolError(
                "max_lines_each must be a positive integer",
                error_code="bad_args",
                field="max_lines_each",
                expected="positive integer",
            )

        results: dict[str, Any] = {}
        for target in targets:
            target_str = str(target)
            try:
                results[target_str] = self._decompile_one(
                    target, timeout_secs=30, max_lines=max_lines_each
                )
            except ToolError as exc:
                results[target_str] = build_error_payload(exc)
            except GhidraBackendError as exc:
                results[target_str] = {
                    "error": str(exc),
                    "error_code": getattr(exc, "error_code", "internal"),
                }
        return {"results": results, "count": len(results)}

    # ---------- pyghidra.exec ---------------------------------------------

    _PYGHIDRA_PRELUDE = (
        "import tinyghidramcp._pyghidra_session as _tgm_sess\n"
        "_tgm_sess.inject(globals())\n"
    )
    # The postlude runs after the agent's code. It maps agent's `result` (the
    # documented convention) onto the upstream eval_code's `_` slot, and
    # persists agent-created globals.
    _PYGHIDRA_POSTLUDE = (
        "\nif 'result' in globals(): _ = result\n"
        "_tgm_globals_size = _tgm_sess.persist(globals())\n"
    )

    def _tool_pyghidra_exec(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute arbitrary Python with persistent globals and bound aliases."""
        import ast
        import time

        from . import _pyghidra_session

        code = arguments.get("code")
        if not isinstance(code, str) or not code:
            raise ToolError(
                "pyghidra.exec requires non-empty 'code'",
                error_code="bad_args",
                field="code",
                expected="string",
            )
        # Auto-detect expression vs script. If the whole agent block parses as
        # a single expression, capture its value as `_` for the upstream eval
        # path. Otherwise run as a script; agents can set `result = ...`.
        try:
            ast.parse(code, mode="eval")
            agent_block = "_ = " + code.strip()
        except SyntaxError:
            agent_block = code
        wrapped = self._PYGHIDRA_PRELUDE + agent_block + self._PYGHIDRA_POSTLUDE
        t0 = time.monotonic()
        try:
            raw = self._backend.eval_code(wrapped, session_id=self._auto_session_id)
        except GhidraBackendError as exc:
            raise ToolError(str(exc), error_code="internal") from exc
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Pull globals_size_bytes out of the eval context if the postlude wrote it.
        # (The upstream doesn't surface arbitrary variables, but it does include
        # stdout/stderr. We instead rely on _pyghidra_session.STATE size after persist.)
        globals_size_bytes = _pyghidra_session._approx_size(_pyghidra_session.STATE)

        result_payload = raw.get("result") if isinstance(raw, dict) else raw
        wrote_program = bool(raw.get("mode_transitioned")) if isinstance(raw, dict) else False
        invalidate_requested = _pyghidra_session.pop_invalidate_request()
        # Flush decompile cache when state may have changed.
        flushed_entries = 0
        if invalidate_requested or wrote_program:
            flushed_entries = self._decompile_cache.invalidate()
        payload: dict[str, Any] = {
            "result": result_payload,
            "duration_ms": duration_ms,
            "globals_size_bytes": globals_size_bytes,
            "wrote_program": wrote_program,
            "cache_invalidate_requested": invalidate_requested,
            "decompile_cache_flushed_entries": flushed_entries,
        }
        if isinstance(raw, dict):
            if raw.get("stdout"):
                payload["stdout"] = raw["stdout"]
            if raw.get("stderr"):
                payload["stderr"] = raw["stderr"]
        return payload

    @staticmethod
    def _tool_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
        try:
            _ = json.dumps(payload, sort_keys=True)
            structured_payload = payload
        except TypeError as exc:
            structured_payload = {
                "error": "tool returned a non-JSON-serializable payload",
                "detail": str(exc),
            }
            is_error = True

        text = SimpleMcpServer._tool_summary_text(structured_payload, is_error=is_error)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured_payload,
            "isError": is_error,
        }

    @staticmethod
    def _tool_summary_text(payload: dict[str, Any], *, is_error: bool) -> str:
        if is_error:
            error = payload.get("error")
            if isinstance(error, str) and error:
                return f"error: {error}"
            return "error"

        keys = (
            "session_id",
            "task_id",
            "status",
            "count",
            "total",
            "offset",
            "limit",
            "read_only",
            "closed",
            "deleted",
            "defined",
        )
        parts = ["ok"]
        for key in keys:
            value = payload.get(key)
            if value is not None:
                parts.append(f"{key}={value}")
        return " ".join(parts)

    def _tool_definitions(self) -> list[dict[str, Any]]:
        return [
            self._tool(
                spec["name"],
                spec["description"],
                spec.get("properties"),
                spec.get("required"),
            )
            for spec in ALL_TOOL_SPECS
        ]

    @staticmethod
    def _tool(
        name: str,
        description: str,
        properties: dict[str, Any] | None = None,
        required: list[str] | tuple[str, ...] | None = None,
        schema_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        input_schema: dict[str, Any] = {
            "type": "object",
            "properties": properties or {},
        }
        if required:
            input_schema["required"] = list(required)
        if schema_extra:
            input_schema.update(schema_extra)
        return {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }

    @staticmethod
    def _success_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error_response(request_id: Any, error: JsonRpcError) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": error.code,
                "message": error.message,
            },
        }
        if error.data is not None:
            payload["error"]["data"] = error.data
        return payload
