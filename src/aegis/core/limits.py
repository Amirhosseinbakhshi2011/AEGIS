"""Runtime enforcement of scan safety limits."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Callable


class RateLimiter:
    """Simple sliding-window limiter: at most ``rate`` acquisitions per minute."""

    def __init__(
        self,
        rate_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = max(1, rate_per_minute)
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = self._clock()
                while self._events and now - self._events[0] >= 60.0:
                    self._events.popleft()
                if len(self._events) < self.rate:
                    self._events.append(now)
                    return
                delay = 60.0 - (now - self._events[0])
            await asyncio.sleep(max(delay, 0.01))
