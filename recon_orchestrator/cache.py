"""
In-memory TTL cache for API response caching.

Reduces redundant DB/container queries for frequently-polled endpoints
like /status, /overview, and /insights. Cache is invalidated on mutations
(POST/PUT/DELETE) and naturally expires via short TTLs.
"""

from __future__ import annotations

import time
from typing import Any


class TTLCache:
    """Simple in-memory TTL cache for API responses.

    Thread-safe for reads (dict.get is atomic in CPython). Writes are not
    locked — acceptable for a cache where worst case is a stale hit for one
    TTL window.
    """

    def __init__(self, ttl_seconds: float = 2.0):
        self._cache: dict[str, tuple[float, Any]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any | None:
        """Return cached value or None if expired/missing."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts, value = entry
        if time.monotonic() - ts > self._ttl:
            # Lazy eviction — only clean on access
            self._cache.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store a value with the current timestamp."""
        self._cache[key] = (time.monotonic(), value)

    def invalidate(self, key_prefix: str = "") -> None:
        """Invalidate entries matching a prefix, or all entries."""
        if key_prefix:
            self._cache = {
                k: v for k, v in self._cache.items()
                if not k.startswith(key_prefix)
            }
        else:
            self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


# Global caches with per-endpoint TTLs
status_cache = TTLCache(ttl_seconds=1.0)     # Status polls — very short TTL
overview_cache = TTLCache(ttl_seconds=3.0)    # Graph overview — medium TTL
insights_cache = TTLCache(ttl_seconds=5.0)    # Insights dashboard — longer TTL
