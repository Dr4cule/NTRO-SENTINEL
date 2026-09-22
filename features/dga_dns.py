from math import log2
from .base import WindowState
def entropy(s):
 c={x:s.count(x) for x in set(s)}; return -sum((n/len(s))*log2(n/len(s)) for n in c.values()) if s else 0
class DNSFeatures:
 def __init__(self): self.state=WindowState(60)
 def update(self,e,ts):
  q=e.get('query',''); label=q.split('.')[0]; vals=self.state.add(e['src_ip']+'|'+q.split('.',1)[-1],ts,e)
  return {'window_seconds':60,'query':q,'label_length':len(label),'label_entropy':round(entropy(label),3),'query_rate':len(vals)/60,'unique_subdomains':len({x.get('query') for x in vals})}
