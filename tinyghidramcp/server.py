"""Minimal MCP (JSON-RPC) server with Ghidra-backed tools."""

from __future__ import annotations

import inspect
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, BinaryIO

from ._version import __version__
from .backend import GhidraBackend, GhidraBackendError

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


BACKEND_TOOL_SPECS: tuple[dict[str, Any], ...] = _build_backend_tool_specs()

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
    """Simple MCP-compatible server exposing Ghidra tools."""

    def __init__(self, backend: Any):
        self._backend = backend
        self._tool_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "meta.help": self._tool_meta_help,
            "decompile.batch": self._tool_decompile_batch,
        }
        for spec in BACKEND_TOOL_SPECS:
            self._tool_handlers[spec["name"]] = self._make_backend_handler(spec["backend_method"])

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
        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str):
            raise JsonRpcError(code=-32602, message="Invalid params: tools/call requires 'name'")
        if not isinstance(arguments, dict):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/call 'arguments' must be an object",
            )

        handler = self._tool_handlers.get(name)
        if handler is None:
            raise JsonRpcError(code=-32601, message=f"Tool not found: {name}")

        try:
            payload = handler(arguments)
            return self._tool_result(payload)
        except GhidraBackendError as exc:
            return self._tool_result({"error": str(exc)}, is_error=True)
        except Exception as exc:  # pragma: no cover - safety net
            return self._tool_result(
                {"error": f"unexpected tool failure: {type(exc).__name__}: {exc}"},
                is_error=True,
            )

    def _make_backend_handler(self, method_name: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
        backend_method = getattr(self._backend, method_name)
        signature = inspect.signature(backend_method)

        def handler(arguments: dict[str, Any]) -> dict[str, Any]:
            try:
                bound = signature.bind(**arguments)
            except TypeError as exc:
                raise GhidraBackendError(str(exc)) from exc
            return backend_method(*bound.args, **bound.kwargs)

        return handler

    def _tool_meta_help(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Return long-form help for a named tool.

        Phase 1c: returns the description from `_DESCRIPTION_OVERRIDES` plus the
        input schema. Phase 2 will replace with hand-written per-tool docs that
        include parameters, examples, and a pyghidra alternative.
        """
        name = arguments.get("tool")
        if not isinstance(name, str) or not name:
            raise GhidraBackendError("meta.help requires a 'tool' string argument")
        spec = next((s for s in ALL_TOOL_SPECS if s.get("name") == name), None)
        if spec is None:
            raise GhidraBackendError(f"unknown tool: {name}")
        return {
            "tool": name,
            "description": _DESCRIPTION_OVERRIDES.get(name, _tool_description(name)),
            "parameters": spec.get("properties", {}),
            "required": spec.get("required", []),
            "examples": [],
            "pyghidra_alternative": "TODO: phase 2 — hand-written per-tool snippet",
        }

    def _tool_decompile_batch(self, _arguments: dict[str, Any]) -> dict[str, Any]:
        """Stub. Phase 2 will implement against a refactored single-program backend."""
        raise GhidraBackendError(
            "decompile.batch is not yet implemented in this build "
            "(error_code: unsupported). Call `decompile` once per target."
        )

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
