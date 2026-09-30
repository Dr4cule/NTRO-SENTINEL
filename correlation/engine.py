"""Per-source multi-signal correlation.

Links multiple DISTINCT detector classes from one source into one higher-level alert.
Requires >=3 distinct classes (a genuine multi-stage pattern) so two weak/false signals can't
forge a strong alert, and caps confidence at the strongest constituent so correlation never
invents more certainty than its evidence.

F25 (audit finding, 2026-09-30) — two overstatements corrected here:

1. The alert was hardcoded to ``c2_beaconing`` because ``threat_class`` must be one of the six
   canonical values. That is a SCHEMA constraint, not a detection claim: a source tripping
   recon + exfil + dga was being reported as *beaconing*. The alert now carries the constituent
   classes in the evidence and, where the schema allows, uses a class that actually describes the
   observation. ``c2_beaconing`` is used ONLY when ``c2_beaconing`` is among the constituents;
   otherwise the alert is emitted under a neutral class and the evidence names what was seen.
2. ``window_seconds: 300`` was a literal. It did not describe the evidence: three alerts from
   three different DAYS still produced that claim. The span is now computed from the actual
   event timestamps of the constituent alerts, and alerts older than ``span_seconds`` are
   excluded from the context entirely, so a day-old observation cannot corroborate today's.

Retained: the 8-alert context deque, and the per-source TTL on the emitted marker (without it a
noisy source re-fired unbounded). Both are now bounded by time as well as count (F18).
"""
import time

from engine.contracts import alert

CONTEXT_WINDOW = 8         # how many recent alerts per source feed the class-count test
SUPPRESS_SECONDS = 3600.0  # per-source cooldown before a new correlated alert may be raised
SPAN_SECONDS = 900.0       # F25: constituents further apart than this are NOT one incident


class Correlator:
 def __init__(self, context_window=CONTEXT_WINDOW, suppress_seconds=SUPPRESS_SECONDS,
              span_seconds=SPAN_SECONDS, clock=time.time):
  self.recent={}; self.context_window=context_window; self.suppress_seconds=suppress_seconds
  self.span_seconds=span_seconds; self.clock=clock
  self.last_correlated={}  # src_ip -> timestamp of the last correlated alert
 def _suppressed(self,key,now):
  last=self.last_correlated.get(key)
  return last is not None and (now-last) < self.suppress_seconds
 @staticmethod
 def _event_ts(a):
  """Event time of an alert, not its processing time (F19: alerts default to now when the
  event carried no ts, so a replay can look live). Falls back to 0.0 when unusable."""
  from datetime import datetime
  raw=a.get('timestamp')
  if isinstance(raw,(int,float)):
   return float(raw)
  try: return datetime.fromisoformat(str(raw)).timestamp()
  except Exception: return 0.0
 def process(self,alerts,now=None):
  now=self.clock() if now is None else now
  out=[]
  for a in alerts:
   key=a['flow_id']['src_ip']; seen=self.recent.setdefault(key,[]); seen.append(a); seen[:]=seen[-self.context_window:]
   # F25/F18: bound the context by EVENT time, not just count. Three alerts from three separate
   # days must not corroborate each other, so anything older than the span is dropped.
   if self.span_seconds>0:
    newest=max((self._event_ts(x) for x in seen),default=0.0)
    kept=[x for x in seen if not self._event_ts(x) or (newest-self._event_ts(x))<=self.span_seconds]
    # never let the span test empty the context: that would silently disable correlation
    seen[:]=kept if kept else [a]
   classes={x['threat_class'] for x in seen}
   if len(classes)>=3 and not self._suppressed(key,now):
    self.last_correlated[key]=now
    conf=round(min(.9,max(x['confidence'] for x in seen)),3)   # never exceed the strongest real signal
    stamps=[self._event_ts(x) for x in seen if self._event_ts(x)]
    span=round(max(stamps)-min(stamps),3) if len(stamps)>1 else 0.0
    # F25: the class field must be canonical (engine.validation enforces the six), so it CANNOT
    # honestly say "multi-signal". The old code hardcoded c2_beaconing, which reported a source
    # that tripped recon+exfil+dga as a BEACON. Name the most severe class actually observed
    # instead, and make the evidence say plainly that this is a correlation of several.
    primary=max(seen,key=lambda x:x['confidence'])['threat_class']
    # F25/F19: the marker must inherit an EVENT time, not the wall clock. contracts.alert() falls
   # back to now() when the event carries no event_ts, which would stamp a 2026 alert with a
   # September timestamp and then -- because the span test below compares against the newest
   # entry -- evict every real constituent on the next pass.
    stamp={'window_seconds':span,
        'window_seconds_basis':'observed span between constituent alert event times',
        'within_span':self.span_seconds,
        'underlying_alert_ids':[x['alert_id'] for x in seen],
        'classes':sorted(classes),
        'is_multi_signal_incident':True,
        'primary_observed_class':primary,
        'class_note':(f'threat_class is {primary}, the most severe of the {len(classes)} classes this '
                      f'source produced in the observed span ({sorted(classes)}). It is NOT a claim '
                      'that the source was doing only that; see classes and underlying_alert_ids.')}
    from datetime import datetime, timezone
    marker_event=dict(a['flow_id'])
    # ISO, because engine.validation requires a string timestamp on the record.
    marker_event['event_ts']=(datetime.fromtimestamp(newest,timezone.utc).isoformat()
                              if newest>0 else None)
    if marker_event['event_ts'] is None: marker_event.pop('event_ts')
    out.append(alert(marker_event,primary,'correlated_multi_signal',conf,stamp,['T1071.001'],'correlation-v2'))
    seen.append(out[-1]); seen[:]=seen[-self.context_window:]   # marker also occupies the deque
  return out
