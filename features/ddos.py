from collections import Counter
from math import log2
from .base import WindowState
class DDoSFeatures:
 def __init__(self): self.state=WindowState(5)
 def update(self,e,ts):
  values=self.state.add(e['dst_ip'],ts,e); sources=[x['src_ip'] for x in values]; syn=sum(x.get('tcp_flags','')=='S' for x in values); udp=sum(x.get('proto')=='udp' for x in values); completed=sum(x.get('conn_state')=='SF' for x in values); counts=Counter(sources);n=len(sources);entropy=-sum((v/n)*log2(v/n) for v in counts.values()) if n else 0
  return {'window_seconds':5,'packet_rate':len(values)/5,'syn_count':syn,'udp_count':udp,'unique_sources':len(counts),'source_ip_entropy':round(entropy,3),'completion_ratio':round(completed/max(1,len(values)),3),'dst_concentration':e['dst_ip'],'inbound_bytes':sum(x.get('resp_bytes',0) for x in values),'outbound_bytes':sum(x.get('orig_bytes',0) for x in values)}
