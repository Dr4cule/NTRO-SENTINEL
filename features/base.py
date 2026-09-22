from __future__ import annotations
from collections import defaultdict, deque
from typing import Any

class WindowState:
    """Bounded, timestamp-based state. Old entries and excess keys are evicted."""
    def __init__(self, window_seconds: float, max_keys: int = 4096):
        self.window_seconds, self.max_keys = window_seconds, max_keys
        self.data: dict[str, deque] = defaultdict(deque)
    def add(self, key: str, ts: float, item: Any) -> list[Any]:
        q = self.data[key]; q.append((ts, item)); self.evict(ts)
        if len(self.data) > self.max_keys:
            oldest = min(self.data, key=lambda k: self.data[k][0][0] if self.data[k] else ts)
            self.data.pop(oldest, None)
        return [x[1] for x in q]
    def evict(self, ts: float) -> None:
        cutoff = ts - self.window_seconds
        for key in list(self.data):
            while self.data[key] and self.data[key][0][0] < cutoff: self.data[key].popleft()
            if not self.data[key]: self.data.pop(key, None)
