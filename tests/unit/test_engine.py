"""Milestone B: engine robustness and determinism."""

import asyncio
import time

from llm_vuln_scan.core.cache import ResponseCache
from llm_vuln_scan.core.ratelimit import TokenBucket
from llm_vuln_scan.targets.http import MISSING, _retry_after, json_path


# --- rate limiter: concurrency is not serialized -----------------------------
async def test_rate_limiter_allows_concurrent_waiters():
    # 10 rps, burst 1. Ten acquires should take ~ (10-1)/10 = 0.9s total, not
    # serialize into a long chain, and crucially they run concurrently: the
    # whole gather finishes near the rate-implied time, not N * something.
    bucket = TokenBucket(rps=20, burst=1)
    start = time.monotonic()
    await asyncio.gather(*(bucket.acquire() for _ in range(10)))
    elapsed = time.monotonic() - start
    # 10 tokens at 20/s with burst 1 -> ~0.45s. Allow generous headroom, but it
    # must be far below a serialized-with-lock-held pathology.
    assert elapsed < 2.0


async def test_rate_limiter_enforces_rate():
    bucket = TokenBucket(rps=50, burst=1)
    start = time.monotonic()
    await asyncio.gather(*(bucket.acquire() for _ in range(10)))
    elapsed = time.monotonic() - start
    # 9 gaps at 1/50s = 0.18s minimum; it must actually throttle, not run free.
    assert elapsed >= 0.12


async def test_rate_limiter_zero_is_noop():
    bucket = TokenBucket(rps=0)
    start = time.monotonic()
    await asyncio.gather(*(bucket.acquire() for _ in range(1000)))
    assert time.monotonic() - start < 0.5


# --- json_path: null vs missing ----------------------------------------------
def test_json_path_distinguishes_null_from_missing():
    assert json_path({"a": None}, "$.a") is None       # present but null
    assert json_path({"a": 1}, "$.b") is MISSING        # absent
    assert json_path({"a": {"b": 2}}, "$.a.b") == 2
    assert json_path({"a": [1, 2]}, "$.a[1]") == 2
    assert json_path({"a": [1]}, "$.a[5]") is MISSING


# --- retry-after parsing -----------------------------------------------------
class _Resp:
    def __init__(self, headers):
        self.headers = headers


def test_retry_after_parses_seconds():
    assert _retry_after(_Resp({"retry-after": "5"})) == 5.0
    assert _retry_after(_Resp({})) is None
    assert _retry_after(_Resp({"retry-after": "not-a-number"})) is None


# --- cache: concurrent writers of the same key do not corrupt -----------------
async def test_cache_concurrent_same_key(tmp_path):
    cache = ResponseCache(tmp_path, enabled=True)
    key = cache.key("same")
    await asyncio.gather(*(
        asyncio.to_thread(cache.put, key, {"text": f"v{i}"}) for i in range(20)
    ))
    got = cache.get(key)
    assert got is not None and got["text"].startswith("v")  # valid, not truncated
    # no leftover temp files
    assert not list(tmp_path.rglob("*.tmp"))
