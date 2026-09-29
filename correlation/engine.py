"""Per-source multi-signal correlation.

Links multiple DISTINCT detector classes from one source into one higher-level alert.
Requires >=3 distinct classes (a genuine multi-stage pattern) so two weak/false signals can't
forge a strong alert, and caps confidence at the strongest constituent so correlation never
invents more certainty than its evidence. Stays in-schema as c2_beaconing/
correlated_multi_signal (threat_class must be one of the six canonical -- see
engine.validation).

Re-fire control: the 8-alert context deque alone was not enough. A source that keeps
producing 3+ classes (a noisy scanner, a busy workstation) flushes the deque's
correlated_multi_signal marker within 8 events, after which correlation fired again on every
subsequent event -- unbounded. The emitted alert_ids are therefore also tracked with a
TTL, so one source yields at most one correlated alert per suppression window.
"""
import time

from engine.contracts import alert

CONTEXT_WINDOW = 8        # how many recent alerts per source feed the class-count test
SUPPRESS_SECONDS = 3600.0 # per-source cooldown before a new correlated alert may be raised


class Correlator:
 def __init__(self, context_window=CONTEXT_WINDOW, suppress_seconds=SUPPRESS_SECONDS, clock=time.time):
  self.recent={}; self.context_window=context_window; self.suppress_seconds=suppress_seconds; self.clock=clock
  self.last_correlated={}  # src_ip -> monotonic-ish timestamp of the last correlated alert
 def _suppressed(self,key,now):
  last=self.last_correlated.get(key)
  return last is not None and (now-last) < self.suppress_seconds
 def process(self,alerts,now=None):
  now=self.clock() if now is None else now
  out=[]
  for a in alerts:
   key=a['flow_id']['src_ip']; seen=self.recent.setdefault(key,[]); seen.append(a); seen[:]=seen[-self.context_window:]
   classes={x['threat_class'] for x in seen}
   if len(classes)>=3 and not self._suppressed(key,now):
    self.last_correlated[key]=now
    conf=round(min(.9,max(x['confidence'] for x in seen)),3)   # never exceed the strongest real signal
    out.append(alert(a['flow_id'],'c2_beaconing','correlated_multi_signal',conf,{'aggregation_key':'src='+key,'window_seconds':300,'underlying_alert_ids':[x['alert_id'] for x in seen],'classes':sorted(classes)},['T1071.001'],'correlation-v1'))
    seen.append(out[-1]); seen[:]=seen[-self.context_window:]   # marker also occupies the deque
  return out
