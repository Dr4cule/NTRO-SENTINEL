from statistics import mean, pstdev
from .base import WindowState
class C2Features:
 def __init__(self): self.state=WindowState(300)
 def update(self,e,ts):
  vals=self.state.add(e['src_ip']+'|'+e['dst_ip'],ts,e); times=[x[0] for x in self.state.data[e['src_ip']+'|'+e['dst_ip']]]; iats=[b-a for a,b in zip(times,times[1:])]
  m=mean(iats) if iats else 0; cv=(pstdev(iats)/m if len(iats)>1 and m else 1)
  return {'window_seconds':300,'session_count':len(vals),'iat_mean':round(m,3),'iat_cv':round(cv,3),'period_seconds':round(m,3),'destination':e['dst_ip'],'destination_port_count':len({x.get('dst_port') for x in vals}),'persistence_seconds':round((times[-1]-times[0]) if len(times)>1 else 0,3)}
