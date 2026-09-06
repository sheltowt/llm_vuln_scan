"""Proactive token-bucket rate limiting.

garak backs off only after a 429 arrives; that wastes requests and trips
provider abuse detection. We shape traffic before it leaves.

The lock is held only long enough to reserve a slot; the wait happens outside
it. An earlier version slept while holding the lock, which forced every call
through one waiter and silently defeated ``run.concurrency`` whenever a rate was
set. Here N callers each reserve quickly and then sleep concurrently, so the
effective throughput is the configured rate and no more.
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
            now = time.monotonic()
            # Refill for elapsed time, capped at capacity.
            self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rps)
            self._updated = now
            if self._tokens >= amount:
                self._tokens -= amount
                wait = 0.0
            else:
                # Reserve future capacity: tokens go negative, which correctly
                # delays every later caller by the amount already spoken for.
                wait = (amount - self._tokens) / self.rps
                self._tokens -= amount
        if wait > 0:
            await asyncio.sleep(wait)
