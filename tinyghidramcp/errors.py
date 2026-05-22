"""Structured error contract.

Every tool error carries an ``error_code`` from a closed taxonomy plus optional
``next_action`` / ``pyghidra_hint`` strings the agent can act on directly. The
server lifts these onto the structured tool response so the caller doesn't have
to parse free-form error text.
"""

from __future__ import annotations

from typing import Any

from .backend import GhidraBackendError

# Closed taxonomy. Add a new value here only after confirming we've classified an
# error path that needs it; "internal" is the catch-all.
ERROR_CODES: frozenset[str] = frozenset(
    [
        "not_found_address",
        "not_found_name",
        "bad_args",
        "state",
        "unsupported",
        "transient",
        "internal",
    ]
)


class ToolError(GhidraBackendError):
    """A GhidraBackendError carrying a structured error contract."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        next_action: str | None = None,
        pyghidra_hint: str | None = None,
        field: str | None = None,
        expected: str | None = None,
        **extra: Any,
    ):
        if error_code not in ERROR_CODES:
            raise ValueError(f"unknown error_code: {error_code!r}")
        super().__init__(message)
        self.error_code = error_code
        self.next_action = next_action
        self.pyghidra_hint = pyghidra_hint
        self.field = field
        self.expected = expected
        self.extra = extra


def build_error_payload(exc: GhidraBackendError) -> dict[str, Any]:
    """Render any GhidraBackendError into the structured response shape."""
    payload: dict[str, Any] = {
        "error": str(exc),
        "error_code": getattr(exc, "error_code", "internal"),
    }
    for attr in ("next_action", "pyghidra_hint", "field", "expected"):
        value = getattr(exc, attr, None)
        if value is not None:
            payload[attr] = value
    extra = getattr(exc, "extra", None)
    if isinstance(extra, dict):
        for k, v in extra.items():
            payload.setdefault(k, v)
    return payload
