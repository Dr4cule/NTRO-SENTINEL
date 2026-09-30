from .base import WindowState, flow_identity
class ReconFeatures:
 def __init__(self): self.state=WindowState(30,dedupe_by=flow_identity)
 def update(self,e,ts):
  vals=self.state.add(e['src_ip'],ts,e)
  hosts={x['dst_ip'] for x in vals}; ports={x['dst_port'] for x in vals}
  failed=sum(x.get('conn_state') in ('S0','REJ') for x in vals)
  # Per-host attempt/failure tallies. A fan-out alert needs to name WHICH host was swept, not
  # merely how many were touched: the alert's flow_id is a single 5-tuple, and defaulting it to
  # whichever flow happened to cross the threshold points analysts at an unrelated CDN edge IP.
  # Bounded to the same MAX_TARGETS as the rendered list; the counts drive the ranking.
  per={}
  for x in vals:
   c=per.setdefault(x['dst_ip'],[0,0]); c[1]+=1
   if x.get('conn_state') in ('S0','REJ'): c[0]+=1
  # rank by failure ratio, then by absolute failures, then name for determinism
  ranked=sorted(per.items(), key=lambda kv:(-(kv[1][0]/kv[1][1]), -kv[1][0], kv[0]))
  return {'window_seconds':30,'unique_dst_hosts':len(hosts),'unique_dst_ports':len(ports),
          'scan_rate':len(vals)/30,'failure_ratio':round(failed/max(1,len(vals)),2),
          'dst_hosts':sorted(hosts)[:64],
          'scan_targets':[{'dst_ip':ip,'failed':c[0],'attempts':c[1],
                           'failure_ratio':round(c[0]/max(1,c[1]),2)} for ip,c in ranked[:8]],
          # the highest-failure host: the most likely actual target of the sweep
          'anchor_dst': ranked[0][0] if ranked else e['dst_ip']}
