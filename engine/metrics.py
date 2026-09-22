from collections import deque
from datetime import datetime, timezone
from time import perf_counter
class StreamMetrics:
 def __init__(self): self.started=perf_counter();self.events=0;self.alerts=0;self.latencies=deque(maxlen=10000)
 def observe(self,latency_ms,alerts):self.events+=1;self.alerts+=alerts;self.latencies.append(latency_ms)
 def snapshot(self,lag=0):
  vals=sorted(self.latencies);q=lambda x:vals[int((len(vals)-1)*x)] if vals else None;elapsed=max(perf_counter()-self.started,.001)
  return {'metric_ts':datetime.now(timezone.utc).isoformat(),'events_total':self.events,'alerts_total':self.alerts,'stream_lag':lag,'throughput_eps':round(self.events/elapsed,2),'p50_latency_ms':round(q(.5),3) if vals else None,'p95_latency_ms':round(q(.95),3) if vals else None,'p99_latency_ms':round(q(.99),3) if vals else None}
