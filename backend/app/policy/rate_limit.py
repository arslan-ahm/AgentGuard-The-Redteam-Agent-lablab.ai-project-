"""Scan rate limits per user and per target (brief 6.9, 13). Owner: Arslan.

``ScanRateLimiter.check(user, target_url)`` is called by ``POST /scans`` before queueing:

- per user: at most ``USER_LIMIT`` scans per ``WINDOW_S`` (stops one account flooding the
  sandbox fleet)
- per target host: at most ``TARGET_LIMIT`` scans per ``WINDOW_S`` across *all* users (stops
  AgentGuard being used to hammer one site)

Sliding window, in memory, async-safe. A refusal carries ``retry_after_s`` for the
``429`` response. One API process is enough for the demo; with several, back this with Redis
(same interface).
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

WINDOW_S = 3600.0
USER_LIMIT = 10
TARGET_LIMIT = 6


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    reason: str = ""
    retry_after_s: float = 0.0


@dataclass
class SlidingWindow:
    """At most ``limit`` hits per ``window_s`` for each key."""

    limit: int
    window_s: float
    clock: Callable[[], float] = time.monotonic
    _hits: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window_s:
            hits.popleft()
        return hits

    def retry_after(self, key: str) -> float:
        """0 if a hit is allowed now, else seconds until the oldest hit expires."""
        now = self.clock()
        hits = self._prune(key, now)
        if not hits:
            del self._hits[key]  # don't keep a deque for every key ever seen
            return 0.0
        if len(hits) < self.limit:
            return 0.0
        return max(0.0, self.window_s - (now - hits[0]))

    def record(self, key: str) -> None:
        self._prune(key, self.clock()).append(self.clock())


def target_key(url: str) -> str:
    """Rate-limit by host (any scheme/port/path of the same site counts together)."""
    try:
        return (urlsplit(url).hostname or url).rstrip(".").lower()
    except ValueError:
        return url


class ScanRateLimiter:
    """Both limits must pass; a hit is recorded only when the scan is allowed."""

    def __init__(
        self,
        user_limit: int = USER_LIMIT,
        target_limit: int = TARGET_LIMIT,
        window_s: float = WINDOW_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.users = SlidingWindow(user_limit, window_s, clock)
        self.targets = SlidingWindow(target_limit, window_s, clock)
        self._lock = asyncio.Lock()

    async def check(self, user: str, target_url: str) -> RateDecision:
        """Allow and record, or refuse with the limit that was hit."""
        host = target_key(target_url)
        async with self._lock:
            wait_user = self.users.retry_after(user)
            if wait_user:
                return RateDecision(False, "too many scans for this user", wait_user)
            wait_target = self.targets.retry_after(host)
            if wait_target:
                return RateDecision(False, f"too many scans of {host}", wait_target)
            self.users.record(user)
            self.targets.record(host)
            return RateDecision(True)
