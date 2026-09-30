from __future__ import annotations
from collections import defaultdict, deque
from typing import Any

class WindowState:
    """Bounded, timestamp-based state. Old entries and excess keys are evicted.

    Three audit findings are addressed here (2026-09-30), all of them about state that was
    bounded on paper but not in practice:

    F16 -- a flow counted twice. Zeek emits an early_event and later a conn for the SAME flow, and
    both entered the detectors, so one connection scored as two sessions. That inflated
    session_count, diluted completion ratios and distorted inter-arrival timing. Entries are now
    keyed by flow identity (``dedupe_by``) and an update REPLACES the earlier record rather than
    appending beside it, so one flow is one session. Byte/flag fields are cumulative in the
    source logs, so the replacement carries the larger totals, not a delta.

    F17 -- late events survived their cutoff. Eviction only ever popped from the FRONT of an
    arrival-ordered deque, so for arrivals t=100, 0, 105 in a 10s window the stale t=0 entry was
    never reached. The front-only prune is kept as the cheap common case, and the amortised sweep
    now drops every expired entry wherever it sits, so out-of-order data is cleaned within
    _SWEEP_EVERY adds instead of surviving for the life of the window.

    F18 -- "bounded" did not mean memory-bounded. max_keys capped the number of KEYS but not the
    events inside each key, so one high-rate host could build an arbitrarily long deque, and the
    dedup/correlation maps had no cap at all. Each key's deque now has max_events, and the
    surviving (oldest-kept) count is exposed so eviction is measurable rather than silent.
    """
    _SWEEP_EVERY = 64

    def __init__(self, window_seconds: float, max_keys: int = 4096, max_events: int = 2048,
                 dedupe_by=None):
        self.window_seconds, self.max_keys = window_seconds, max_keys
        self.max_events = max_events
        self.dedupe_by = dedupe_by
        self.data: dict[str, deque] = defaultdict(deque)
        self._adds = 0
        self.dropped_out_of_order = 0
        self.trimmed_over_max_events = 0

    @staticmethod
    def _identity(item: Any, dedupe_by):
        if not dedupe_by or not isinstance(item, dict):
            return None
        # A callable resolver, so an adapter with no uid can fall back to the 5-tuple instead
        # of every record collapsing onto the same (None,) identity.
        if callable(dedupe_by):
            try: return dedupe_by(item)
            except Exception: return None
        try:
            return tuple(item.get(k) for k in dedupe_by)
        except Exception:
            return None

    def add(self, key: str, ts: float, item: Any, dedupe_by=None) -> list[Any]:
        q = self.data[key]
        if dedupe_by is None: dedupe_by = self.dedupe_by
        ident = self._identity(item, dedupe_by)
        # F16, precisely scoped. A flow is over-counted when Zeek's early_event and the later
        # conn for the SAME connection both enter the detectors. That is the only case merged
        # here. Two `conn` records are NOT merged unless they carry the same uid, because a host
        # may legitimately open a second connection on a previously-used source port -- merging
        # on the 5-tuple alone would delete a real session and blind the detector to a beacon
        # from a malware that pins its source port.
        has_uid = isinstance(item, dict) and bool(item.get('uid'))
        kind = item.get('kind') if isinstance(item, dict) else None
        if ident is None:
            q.append((ts, item))
        else:
            for i, (_t, existing) in enumerate(q):
                if self._identity(existing, dedupe_by) != ident:
                    continue
                same_uid = has_uid and isinstance(existing, dict) and bool(existing.get('uid'))
                early_then_final = (isinstance(existing, dict) and existing.get('kind') == 'early_event'
                                    and kind == 'conn')
                if same_uid or early_then_final:
                    del q[i]
                    break
            q.append((ts, item))
        self._prune_front(q, ts)
        self._adds += 1
        if self._adds >= self._SWEEP_EVERY:
            self._sweep(ts)
        # The cross-key sweep is amortised. An "or over capacity" condition here would sweep on
        # every add for a high-cardinality flow (a spoofed-source flood is nothing but high
        # cardinality) and restore the original O(events x keys) cost exactly under attack.
        if len(self.data) > self.max_keys:
            self._trim_keys(ts)
        # F18: cap events per key, oldest first, and count what was dropped.
        while len(q) > self.max_events:
            q.popleft()
            self.trimmed_over_max_events += 1
        return [x[1] for x in q]

    def _prune_front(self, q: deque, ts: float) -> None:
        """Cheap path: drop from the front while expired. Correct when arrivals are in order."""
        cutoff = ts - self.window_seconds
        while q and q[0][0] < cutoff:
            q.popleft()

    def _sweep(self, ts: float) -> None:
        """F17: full pass. Removes every expired entry WHEREVER it sits, so a late or replayed
        event cannot sit in the window past its cutoff because it arrived out of order."""
        cutoff = ts - self.window_seconds
        for key in list(self.data):
            d = self.data[key]
            if not d:
                self.data.pop(key, None)
                continue
            kept = [e for e in d if e[0] >= cutoff]
            if len(kept) != len(d):
                self.dropped_out_of_order += len(d) - len(kept)
                d.clear()
                d.extend(kept)
                if not d:
                    self.data.pop(key, None)
        self._adds = 0

    def _trim_keys(self, ts: float) -> None:
        while len(self.data) > self.max_keys:
            oldest = min(self.data,
                         key=lambda k: self.data[k][0][0] if self.data[k] else ts)
            self.data.pop(oldest, None)

    def evict(self, ts: float) -> None:
        self._sweep(ts)

    def stats(self) -> dict[str, int]:
        return {'keys': len(self.data), 'max_keys': self.max_keys,
                'max_events_per_key': self.max_events,
                'dropped_out_of_order': self.dropped_out_of_order,
                'trimmed_over_max_events': self.trimmed_over_max_events}


def flow_identity(e):
    """The field tuple that identifies ONE connection in a telemetry record.

    Zeek supplies a ``uid`` that is stable across a flow's early/update/final records, so it is
    the strongest identity available. Adapters that cannot supply one (the scapy live path) fall
    back to the 5-tuple, which is unique per connection. Returns None for anything that is not a
    flow record, so non-conn events (a DNS question has no flow of its own) are never de-duplicated
    against each other."""
    if not isinstance(e, dict):
        return None
    uid = e.get('uid')
    if uid:
        return ('uid', uid)
    if e.get('src_ip') and e.get('dst_ip') is not None:
        return ('flow', e.get('src_ip'), e.get('src_port'), e.get('dst_ip'),
                e.get('dst_port'), e.get('proto'))
    return None
