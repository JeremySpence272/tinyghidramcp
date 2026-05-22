"""JSONL telemetry for tinyghidramcp tool calls.

One file per session. Records every tool call, pre-dispatch error, and the
session-start banner. Configured via env vars:

- ``TINYGHIDRAMCP_TELEMETRY_DIR`` -- output directory.
  Default: ``/tmp/tinyghidramcp_telemetry/``.
  Empty string disables telemetry (for hermetic tests).

- ``TINYGHIDRAMCP_SESSION_ID`` -- session id used as both the filename suffix
  (``session_<id>.jsonl``) and the ``session`` field on every record. Default:
  a fresh UUID4 generated at server start. No validation on format.

Per-call records are flushed and fsynced on write so a crashing server doesn't
lose its tail.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

DEFAULT_DIR = "/tmp/tinyghidramcp_telemetry/"
MAX_STRING_ARG_LEN = 1024
PREVIEW_CHARS = 200


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _truncate_arg(value: Any) -> tuple[Any, bool]:
    if isinstance(value, str) and len(value) > MAX_STRING_ARG_LEN:
        return value[:MAX_STRING_ARG_LEN], True
    return value, False


def _redact_args(args: Any) -> tuple[Any, bool]:
    if not isinstance(args, dict):
        return args, False
    out: dict[str, Any] = {}
    any_truncated = False
    for k, v in args.items():
        new_v, truncated = _truncate_arg(v)
        out[k] = new_v
        if truncated:
            any_truncated = True
    return out, any_truncated


def _sha256_of_file(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Telemetry:
    """Append-only JSONL recorder for a single session."""

    def __init__(self, dir_path: str | None, session_id: str):
        self.session_id = session_id
        self._fp = None
        self._path: str | None = None
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
            self._path = os.path.join(dir_path, f"session_{session_id}.jsonl")
            self._fp = open(self._path, "a", encoding="utf-8")

    @property
    def enabled(self) -> bool:
        return self._fp is not None

    @property
    def path(self) -> str | None:
        return self._path

    def emit(self, record: dict[str, Any]) -> None:
        if self._fp is None:
            return
        record.setdefault("ts", _now_iso())
        record.setdefault("session", self.session_id)
        self._fp.write(json.dumps(record, default=str) + "\n")
        self._fp.flush()
        try:
            os.fsync(self._fp.fileno())
        except OSError:
            pass

    def emit_session_start(
        self,
        *,
        ghidra_version: str | None = None,
        git_sha: str | None = None,
        binary_path: str | None = None,
        bootstrap_status: str = "ok",
        bootstrap_error: str | None = None,
    ) -> None:
        """Single shape for every session-start record. ``bootstrap_status`` is
        "ok" on success, "failed" if the warmed-project open didn't work.
        Analyzer reads the first line of every JSONL session file and inspects
        this field to know whether to expect further records."""
        self.emit(
            {
                "event": "session_start",
                "ghidra_version": ghidra_version,
                "tinyghidramcp_git_sha": git_sha,
                "binary_path": binary_path,
                "binary_sha256": _sha256_of_file(binary_path) if binary_path else None,
                "bootstrap_status": bootstrap_status,
                "bootstrap_error": bootstrap_error,
            }
        )

    def emit_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        status: str,
        error_code: str | None,
        latency_ms: int,
        result_size_bytes: int,
        result_preview: str,
        cached: bool = False,
        address_adjusted: dict[str, Any] | None = None,
        code: str | None = None,
        globals_size_bytes: int | None = None,
    ) -> None:
        redacted, truncated = _redact_args(args)
        record: dict[str, Any] = {
            "event": "tool_call",
            "tool": tool,
            "args": redacted,
            "args_truncated": truncated,
            "status": status,
            "error_code": error_code,
            "latency_ms": latency_ms,
            "result_size_bytes": result_size_bytes,
            "result_preview": result_preview[:PREVIEW_CHARS] if result_preview else "",
            "cached": cached,
            "address_adjusted": address_adjusted,
        }
        if code is not None:
            record["code"] = code  # full body, never truncated for pyghidra.exec
        if globals_size_bytes is not None:
            record["globals_size_bytes"] = globals_size_bytes
        self.emit(record)

    def emit_pre_dispatch_error(
        self,
        *,
        error_code: str,
        tool: str | None = None,
        requested_tool: str | None = None,
        validation_field: str | None = None,
        validation_expected: str | None = None,
        raw_args_preview: str | None = None,
        message: str | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "event": "tool_call",
            "tool": tool,
            "status": "pre_dispatch_error",
            "error_code": error_code,
            "message": message,
        }
        if requested_tool is not None:
            record["requested_tool"] = requested_tool
        if validation_field is not None:
            record["validation_field"] = validation_field
        if validation_expected is not None:
            record["validation_expected"] = validation_expected
        if raw_args_preview is not None:
            record["raw_args_preview"] = raw_args_preview[:PREVIEW_CHARS]
        self.emit(record)

    def close(self) -> None:
        if self._fp is not None:
            self._fp.close()
            self._fp = None


def from_env() -> Telemetry:
    """Construct a Telemetry from the documented env vars."""
    dir_value = os.environ.get("TINYGHIDRAMCP_TELEMETRY_DIR")
    if dir_value is None:
        dir_path: str | None = DEFAULT_DIR
    elif dir_value == "":
        dir_path = None  # explicitly disabled
    else:
        dir_path = dir_value

    session_id = os.environ.get("TINYGHIDRAMCP_SESSION_ID") or str(uuid.uuid4())
    return Telemetry(dir_path, session_id)
