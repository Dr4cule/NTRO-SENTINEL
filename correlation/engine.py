from engine.contracts import alert
class Correlator:
 def __init__(self): self.recent={}
 def process(self,alerts):
  out=[]
  for a in alerts:
   key=a['flow_id']['src_ip']; seen=self.recent.setdefault(key,[]); seen.append(a); seen[:]=seen[-8:]
   classes={x['threat_class'] for x in seen}
   if len(classes)>=2 and not any(x['threat_class']=='c2_beaconing' and x['subtype']=='correlated_multi_signal' for x in seen):
    out.append(alert(a['flow_id'],'c2_beaconing','correlated_multi_signal',.85,{'aggregation_key':'src='+key,'window_seconds':300,'underlying_alert_ids':[x['alert_id'] for x in seen],'classes':sorted(classes)},['T1071.001'],'correlation-v1'))
  return out
