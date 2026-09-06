"""Proactive token-bucket rate limiting.

garak backs off only after a 429 arrives; that wastes requests and trips
provider abuse detection. We shape traffic before it leaves.
"""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, rps: float = 0.0, burst: int = 1) -> None:
        self.rps = max(0.0, rps)
        self.capacity = max(1, burst)
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, amount: float = 1.0) -> None:
        if self.rps <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rps
                )
                self._updated = now
                if self._tokens >= amount:
                    self._tokens -= amount
                    return
                await asyncio.sleep((amount - self._tokens) / self.rps)
