"""Content-addressed response cache.

Keyed by the target identifier plus the exact request, so replaying a committed
suite against an unchanged target costs nothing and stays deterministic.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from .models import content_hash


class ResponseCache:
    def __init__(self, directory: str | Path | None, enabled: bool = True) -> None:
        self.enabled = enabled and directory is not None
        self.dir = Path(directory) if directory else None
        self.hits = 0
        self.misses = 0
        if self.enabled and self.dir:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        assert self.dir is not None
        return self.dir / key[:2] / f"{key}.json"

    def key(self, *parts: Any) -> str:
        return content_hash(list(parts))

    def get(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        path = self._path(key)
        if not path.exists():
            self.misses += 1
            return None
        try:
            value = json.loads(path.read_text())
            self.hits += 1
            return value
        except (OSError, json.JSONDecodeError):
            self.misses += 1
            return None

    def put(self, key: str, value: dict[str, Any]) -> None:
        if not self.enabled:
            return
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # A unique temp name per write, so two concurrent writers of the same key
        # (e.g. two identical judge calls in flight) cannot clobber each other's
        # temp file mid-write. The final rename stays atomic.
        tmp = path.with_suffix(f".{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        try:
            tmp.write_text(json.dumps(value, default=str))
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)
