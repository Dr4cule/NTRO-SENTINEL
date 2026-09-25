from engine.contracts import alert
class Correlator:
 """Link multiple DISTINCT detector classes from one source into one higher-level alert.
 Requires >=3 distinct classes (a genuine multi-stage pattern) so two weak/false signals
 can't forge a strong alert, and caps confidence at the strongest constituent so correlation
 never invents more certainty than its evidence. Stays in-schema as c2_beaconing/
 correlated_multi_signal (threat_class must be one of the six canonical -- see engine.validation)."""
 def __init__(self): self.recent={}
 def process(self,alerts):
  out=[]
  for a in alerts:
   key=a['flow_id']['src_ip']; seen=self.recent.setdefault(key,[]); seen.append(a); seen[:]=seen[-8:]
   classes={x['threat_class'] for x in seen}
   if len(classes)>=3 and not any(x['threat_class']=='c2_beaconing' and x['subtype']=='correlated_multi_signal' for x in seen):
    conf=round(min(.9,max(x['confidence'] for x in seen)),3)   # never exceed the strongest real signal
    out.append(alert(a['flow_id'],'c2_beaconing','correlated_multi_signal',conf,{'aggregation_key':'src='+key,'window_seconds':300,'underlying_alert_ids':[x['alert_id'] for x in seen],'classes':sorted(classes)},['T1071.001'],'correlation-v1'))
  return out
