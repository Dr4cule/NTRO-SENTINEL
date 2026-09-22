from .base import WindowState
class ExfilFeatures:
 def __init__(self): self.state=WindowState(300)
 def update(self,e,ts):
  vals=self.state.add(e['src_ip']+'|'+e['dst_ip'],ts,e); out=sum(x.get('orig_bytes',0) for x in vals); inn=sum(x.get('resp_bytes',0) for x in vals)
  return {'window_seconds':300,'outbound_bytes':out,'inbound_bytes':inn,'outbound_inbound_ratio':round(out/max(1,inn),2),'session_count':len(vals),'destination':e['dst_ip']}
