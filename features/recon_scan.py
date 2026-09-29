from .base import WindowState
class ReconFeatures:
 def __init__(self): self.state=WindowState(30)
 def update(self,e,ts):
  vals=self.state.add(e['src_ip'],ts,e); hosts={x['dst_ip'] for x in vals}; ports={x['dst_port'] for x in vals}; failed=sum(x.get('conn_state') in ('S0','REJ') for x in vals)
  # dst_hosts is carried (bounded by the window) so the detector can ask how the fan-out is
  # DISTRIBUTED across networks, not just how wide it is. A browser fans out across many CDN/edge
  # ASNs; a sweep enumerates within one network. Without this the rule cannot tell them apart.
  return {'window_seconds':30,'unique_dst_hosts':len(hosts),'unique_dst_ports':len(ports),'scan_rate':len(vals)/30,'failure_ratio':round(failed/max(1,len(vals)),2),'dst_hosts':sorted(hosts)[:64]}
