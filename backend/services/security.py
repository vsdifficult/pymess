from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta


class ReplayProtector:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.seen: dict[str, datetime] = {}

    def validate(self, nonce: str, timestamp: datetime) -> bool:
        now = datetime.now(timezone.utc)
        ts = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        if abs(now - ts) > self.ttl:
            return False
        if nonce in self.seen and now - self.seen[nonce] <= self.ttl:
            return False
        self.seen[nonce] = now
        expired = [k for k, v in self.seen.items() if now - v > self.ttl]
        for key in expired:
            del self.seen[key]
        return True


class RateLimiter:
    def __init__(self, max_requests: int = 30, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests: dict[str, deque[datetime]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = datetime.now(timezone.utc)
        q = self.requests[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_requests:
            return False
        q.append(now)
        return True
