from __future__ import annotations
from collections import defaultdict, deque
from typing import Any

class WindowState:
    """Bounded, timestamp-based state. Old entries and excess keys are evicted."""
    # A full sweep visits EVERY key, so running one per add() costs O(events x keys). Measured
    # on the real pipeline that collapses throughput from ~1200 ev/s at 2k events to ~170 ev/s
    # at 16k, because each of the six feature extractors re-swept its whole keyspace for every
    # packet -- a 7.8 MB upload (75k events) needed ~7 minutes and looked like a hang. The
    # sweep is therefore amortised: the key being written is always pruned immediately (which
    # is what bounds a hot key, and what the eviction tests exercise), and the cross-key sweep
    # runs every _SWEEP_EVERY adds or as soon as the key cap is reached. Memory stays bounded
    # by max_keys, and stale keys survive at most _SWEEP_EVERY extra adds.
    _SWEEP_EVERY = 64
    def __init__(self, window_seconds: float, max_keys: int = 4096):
        self.window_seconds, self.max_keys = window_seconds, max_keys
        self.data: dict[str, deque] = defaultdict(deque)
        self._adds = 0
    def add(self, key: str, ts: float, item: Any) -> list[Any]:
        q = self.data[key]; q.append((ts, item))
        self._prune(q, ts)
        self._adds += 1
        # Trigger ONLY on the counter, never on len(data) > max_keys. A high-cardinality flow
        # (a spoofed-source flood is nothing but high cardinality) keeps the keycount above the
        # cap continuously, so an "or over capacity" condition sweeps on EVERY add and restores
        # the original O(events x keys) cost exactly when the sensor is under attack. Trimming
        # inside the amortised sweep instead leaves at most _SWEEP_EVERY keys above the cap.
        if self._adds >= self._SWEEP_EVERY: self._sweep(ts)
        return [x[1] for x in q]
    def _prune(self, q: deque, ts: float) -> None:
        cutoff = ts - self.window_seconds
        while q and q[0][0] < cutoff: q.popleft()
    def _sweep(self, ts: float) -> None:
        cutoff = ts - self.window_seconds
        for key in list(self.data):
            self._prune(self.data[key], ts)
            if not self.data[key]: self.data.pop(key, None)
        # The key cap is enforced HERE, not per add. Finding the oldest key is an O(keys) min()
        # scan, and doing it on every add once the window is full was the second half of the
        # quadratic: six extractors x 4096 keys per event, which pinned throughput near 130 ev/s
        # by 16k events. At most _SWEEP_EVERY extra keys can exist above the cap, which is a
        # far tighter bound than the unbounded growth it replaces.
        while len(self.data) > self.max_keys:
            oldest = min(self.data, key=lambda k: self.data[k][0][0] if self.data[k] else ts)
            self.data.pop(oldest, None)
        self._adds = 0
    def evict(self, ts: float) -> None:
        self._sweep(ts)
