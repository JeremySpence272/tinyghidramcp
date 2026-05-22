"""In-process LRU cache for decompile responses.

Keyed by ``(resolved_address, timeout_secs)``. The canonical resolved address
comes out of the address-tolerance pipeline, so two requests that resolve to
the same function entry share a cache entry even if the agent passed different
inputs (one a name, one an offset, one a PLT thunk).

Cap is 256 MB. Size is measured by JSON-serialised length of cached values.
Cap and key shape are compile-time constants -- no env override.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any

MAX_BYTES_DEFAULT = 256 * 1024 * 1024


class DecompileCache:
    def __init__(self, max_bytes: int = MAX_BYTES_DEFAULT):
        self._cache: OrderedDict[tuple, dict[str, Any]] = OrderedDict()
        self._sizes: dict[tuple, int] = {}
        self._max_bytes = max_bytes
        self._total_size = 0
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _size_of(value: Any) -> int:
        try:
            return len(json.dumps(value, default=str))
        except Exception:
            return 1024  # conservative fallback

    def get(self, key: tuple) -> dict[str, Any] | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            self.hits += 1
            return self._cache[key]
        self.misses += 1
        return None

    def put(self, key: tuple, value: dict[str, Any]) -> None:
        if key in self._cache:
            self._total_size -= self._sizes.get(key, 0)
        size = self._size_of(value)
        self._cache[key] = value
        self._sizes[key] = size
        self._total_size += size
        while self._total_size > self._max_bytes and self._cache:
            evicted_key, _ = self._cache.popitem(last=False)
            self._total_size -= self._sizes.pop(evicted_key, 0)

    def invalidate(self) -> int:
        """Flush everything. Returns the number of entries evicted."""
        count = len(self._cache)
        self._cache.clear()
        self._sizes.clear()
        self._total_size = 0
        return count

    @property
    def size_bytes(self) -> int:
        return self._total_size

    @property
    def entries(self) -> int:
        return len(self._cache)
