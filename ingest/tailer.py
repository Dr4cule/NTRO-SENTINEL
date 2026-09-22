"""Incrementally normalize Zeek JSON logs without copying packet payloads."""
import argparse,json,os,sys,time
from pathlib import Path

def endpoint(r):
 i=r.get('id',{})
 def port(value):
  if isinstance(value,int): return value
  try: return int(str(value).split('/',1)[0])
  except (TypeError,ValueError): return 0
 return {'src_ip':r.get('src_ip',r.get('id.orig_h',i.get('orig_h',''))),'src_port':port(r.get('src_port',r.get('id.orig_p',i.get('orig_p',0)))),'dst_ip':r.get('dst_ip',r.get('id.resp_h',i.get('resp_h',''))),'dst_port':port(r.get('dst_port',r.get('id.resp_p',i.get('resp_p',0)))),'proto':r.get('proto','')}

def normalize(record, log_name):
 """Maps only metadata used by the detectors; raw payload is intentionally absent."""
 base={'ts':record.get('ts',time.time()),**endpoint(record),'uid':record.get('uid','')}
 if log_name=='dns':
  return {**base,'kind':'dns','query':record.get('query',''),'qtype':record.get('qtype_name',record.get('qtype','')),'rcode':record.get('rcode_name',record.get('rcode','')),'answers_count':len(record.get('answers',[]))}
 if log_name in {'ssl','tls'}:
  return {**base,'kind':'tls','tls':True,'tls_version':record.get('version','unknown'),'sni':record.get('server_name',''),'ja3':record.get('ja3',''),'ja4':record.get('ja4',''),'cipher':record.get('cipher',''),'resumed':record.get('resumed',False),'established':record.get('established',False)}
 if log_name=='x509':
  return {**base,'kind':'tls_certificate','tls':True,'certificate_subject':record.get('subject',''),'certificate_issuer':record.get('issuer',''),'certificate_validity':record.get('certificate.version','')}
 if log_name=='early': return {**base,'kind':'early_event'}
 return {**base,'kind':'conn','orig_bytes':record.get('orig_bytes',record.get('orig_ip_bytes',0)),'resp_bytes':record.get('resp_bytes',record.get('resp_ip_bytes',0)),'conn_state':record.get('conn_state',''),'duration':record.get('duration',0),'tcp_flags':record.get('history','')[:1]}

def follow(path, once=False):
 with open(path) as f:
  while True:
   line=f.readline()
   if line:
    yield normalize(json.loads(line),Path(path).stem)
   elif once: return
   else: time.sleep(.1)

def publish(events, redis_url=None):
 client=None
 if redis_url:
  import redis; client=redis.Redis.from_url(redis_url,decode_responses=True)
 for x in events:
  if client: client.xadd('telemetry',{'record':json.dumps(x,separators=(',',':'))},maxlen=100000,approximate=True)
  else: print(json.dumps(x),flush=True)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('log');parser.add_argument('--redis-url',default=os.getenv('REDIS_URL'));parser.add_argument('--once',action='store_true',help='process current log contents then exit');args=parser.parse_args()
 publish(follow(args.log,args.once),args.redis_url)
