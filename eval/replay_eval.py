#!/usr/bin/env python3
import argparse, json, os, time
from pathlib import Path
from engine.stream_consumer import Pipeline
def main():
 artifact_dir=os.getenv('ARTIFACT_DIR','artifacts');a=argparse.ArgumentParser();a.add_argument('scenario');a.add_argument('--pace',type=float,default=0);a.add_argument('--output',default=str(Path(artifact_dir)/'detector_alerts.jsonl'));a.add_argument('--redis-url',default=None);args=a.parse_args()
 client=None
 if args.redis_url:
  import redis; client=redis.Redis.from_url(args.redis_url,decode_responses=True)
 p=Pipeline(); start=time.perf_counter(); events=alerts=0; lats=[]; out=Path(args.output);out.parent.mkdir(exist_ok=True)
 with open(args.scenario) as src,out.open('w') as dst:
  for line in src:
   events+=1; ing=time.perf_counter(); event=json.loads(line)
   if client: client.xadd('telemetry',{'record':json.dumps(event,separators=(',',':'))},maxlen=100000,approximate=True)
   for x in p.process(event):
    lats.append((time.perf_counter()-ing)*1000);dst.write(json.dumps(x)+'\n');dst.flush();alerts+=1
   if args.pace:time.sleep(args.pace)
 elapsed=time.perf_counter()-start
 q=lambda n:sorted(lats)[int((len(lats)-1)*n)] if lats else None
 metrics={'events':events,'alerts':alerts,'elapsed_seconds':round(elapsed,4),'events_per_second':round(events/max(elapsed,.0001),2),'alert_latency_ms':{'definition':'event ingestion to alert serialization','p50':q(.5),'p95':q(.95),'p99':q(.99)}}
 Path(artifact_dir).mkdir(parents=True,exist_ok=True);Path(artifact_dir,'metrics.json').write_text(json.dumps(metrics,indent=2)); print(json.dumps(metrics,indent=2))
if __name__=='__main__':main()
