"""Small in-process sliding-window rate limiter (per client IP and bucket).

The API runs as a single uvicorn process per container; account lockout (DB-backed)
remains the authoritative brute-force control. For multi-replica deployments put a
shared limiter (e.g. nginx limit_req, already configured) in front.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, bucket: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[(bucket, key)]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 50_000:
                self._hits.clear()
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
