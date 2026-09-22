from .base import WindowState
class TLSFeatures:
 def __init__(self): self.state=WindowState(30)
 def update(self,e,ts):
  vals=self.state.add(e['src_ip'],ts,e); out=e.get('orig_bytes',0); inn=e.get('resp_bytes',0)
  return {'window_seconds':30,'ja3':e.get('ja3',''),'ja4':e.get('ja4',''),'tls_version':e.get('tls_version','unknown'),'sni':e.get('sni',''),'outbound_inbound_ratio':round(out/max(1,inn),2),'duration':e.get('duration',0),'host_sessions':len(vals)}
