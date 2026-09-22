"""Incremental JSONL consumer; Redis Streams is optional through REDIS_URL."""
from __future__ import annotations
import json, os, time
from datetime import datetime
from pathlib import Path
from features.ddos import DDoSFeatures
from features.c2_beacon import C2Features
from features.dga_dns import DNSFeatures
from features.tls_metadata import TLSFeatures
from features.recon_scan import ReconFeatures
from features.exfiltration import ExfilFeatures
from detectors import rules
from correlation.engine import Correlator
from engine.metrics import StreamMetrics
from alertstore.store import AlertStore

class Pipeline:
 def __init__(self):
  self.features={'ddos':DDoSFeatures(),'c2':C2Features(),'dns':DNSFeatures(),'tls':TLSFeatures(),'recon':ReconFeatures(),'exfil':ExfilFeatures()}; self.correlation=Correlator(); self.emitted={}
 def process(self,e):
  ts=float(e.get('ts',time.time())); candidates=[]
  if e.get('kind') in ('conn','early_event'):
   candidates += [rules.ddos(e,self.features['ddos'].update(e,ts)),rules.c2(e,self.features['c2'].update(e,ts)),rules.recon(e,self.features['recon'].update(e,ts)),rules.exfil(e,self.features['exfil'].update(e,ts))]
  if e.get('kind')=='dns': candidates.append(rules.dns(e,self.features['dns'].update(e,ts)))
  if e.get('tls'): candidates.append(rules.encrypted(e,self.features['tls'].update(e,ts)))
  fresh=[]
  for item in (x for x in candidates if x):
   evidence=item['supporting_evidence']; key=(item['threat_class'],item['subtype'],evidence.get('aggregation_key',item['flow_id']['src_ip']+'|'+item['flow_id']['dst_ip']))
   if ts-self.emitted.get(key,float('-inf'))>=30: self.emitted[key]=ts;fresh.append(item)
  return fresh + self.correlation.process(fresh)

def redis_worker(redis_url=os.getenv('REDIS_URL','redis://redis:6379/0'), stream='telemetry', group='sentinel', consumer='worker-1'):
 """Consume Redis Streams continuously; this is the deployed streaming path."""
 try:
  import redis
 except ImportError as exc: raise RuntimeError('Install redis dependency for Redis Streams mode') from exc
 client=redis.Redis.from_url(redis_url,decode_responses=True); store=AlertStore(); pipeline=Pipeline(); metrics=StreamMetrics()
 try: client.xgroup_create(stream,group,id='0',mkstream=True)
 except redis.ResponseError: pass
 while True:
  rows=client.xreadgroup(group,consumer,{stream:'>'},count=100,block=1000)
  for _,messages in rows:
   for message_id, fields in messages:
    started=time.perf_counter(); event=json.loads(fields['record']); alerts=pipeline.process(event)
    for item in alerts: store.append(item)
    metrics.observe((time.perf_counter()-started)*1000,len(alerts)); client.xack(stream,group,message_id)
  store.metric(**metrics.snapshot())

def run_jsonl(source, destination='artifacts/detector_alerts.jsonl', pace=0):
 p=Pipeline(); out=Path(destination); out.parent.mkdir(exist_ok=True); count=0
 with open(source) as src, out.open('w') as dst:
  for line in src:
   if not line.strip(): continue
   for a in p.process(json.loads(line)):
    dst.write(json.dumps(a)+'\n'); dst.flush(); count+=1
   if pace: time.sleep(pace)
 return count

if __name__=='__main__':
 redis_worker()
