"""Sentinel API and live dashboard delivery surface."""
from __future__ import annotations
import asyncio
import os
import tempfile
from pathlib import Path
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from alertstore.store import AlertStore
from ingest.service import MAX_UPLOAD_BYTES
from api.auth import require_write_token, write_auth_enabled, configured_token

app=FastAPI(title='NTRO Sentinel',version='1.0.0',description='Passive, payload-blind threat intelligence')
store=AlertStore()
class IncomingAlert(BaseModel):
 alert_id:str; timestamp:str; flow_id:dict; threat_class:str; subtype:str; confidence:float; severity:str; supporting_evidence:dict; mitre_attack:list[str]; model_version:str

@app.get('/health')
def health():
 s=store.summary()
 return {'status':'ok','version':app.version,'store':'sqlite','chain':store.verify_chain(),
         'pipeline':s['pipeline'],'write_auth':write_auth_enabled(),'max_upload_mb':MAX_UPLOAD_BYTES//(1024*1024)}

@app.get('/api/alerts')
def alerts(threat_class:str|None=None,severity:str|None=None,limit:int=Query(250,ge=1,le=1000)): return store.list(threat_class,severity,limit)

@app.post('/api/alerts',status_code=201,dependencies=[Depends(require_write_token)])
def add_alert(item:IncomingAlert): return {'created':store.append(item.model_dump())}

@app.post('/api/ingest',dependencies=[Depends(require_write_token)])
async def ingest_capture(request:Request):
 # The body is streamed to a temp file in fixed-size chunks and aborted the moment it passes
 # MAX_UPLOAD_BYTES, so a large capture never has to fit in memory (the previous version read
 # the whole body via request.body() under a cap larger than this container's memory limit).
 # ponytail: in Docker the redis worker is the live writer; a concurrent upload while it writes
 # can race the hash chain (safe when the worker is idle — the default compose).
 from ingest.service import ingest_upload_path
 name=request.headers.get('x-filename','upload.jsonl')
 declared=request.headers.get('content-length')
 if declared:
  try:
   if int(declared) > MAX_UPLOAD_BYTES:
    raise HTTPException(status_code=413,detail=f'upload exceeds {MAX_UPLOAD_BYTES//(1024*1024)} MB cap')
  except ValueError:
   pass
 written=0; tmp=None
 try:
  with tempfile.NamedTemporaryFile(suffix=Path(name).suffix.lower() or '.bin',delete=False) as tf:
   tmp=tf.name
   async for chunk in request.stream():
    written+=len(chunk)
    if written>MAX_UPLOAD_BYTES:
     raise HTTPException(status_code=413,detail=f'upload exceeds {MAX_UPLOAD_BYTES//(1024*1024)} MB cap')
    tf.write(chunk)
  if not written: raise HTTPException(status_code=400,detail='empty upload')
  return await run_in_threadpool(ingest_upload_path,name,tmp)
 except HTTPException: raise
 except ValueError as e: raise HTTPException(status_code=400,detail=str(e))
 finally:
  if tmp:
   try: os.unlink(tmp)
   except OSError: pass

@app.get('/api/dashboard/summary')
def summary(): return store.summary()
@app.get('/api/metrics')
def metrics(): return store.summary()['pipeline']
@app.get('/api/evidence/verify')
def evidence_integrity(): return store.verify_chain()
@app.get('/api/incidents')
def incidents():
 grouped={}
 for a in store.list(limit=1000):
  key=a['flow_id']['src_ip']; x=grouped.setdefault(key,{'source':key,'risk':0,'classes':set(),'alerts':[]});x['risk']=min(100,x['risk']+round(a['confidence']*18));x['classes'].add(a['threat_class']);x['alerts'].append(a)
 return sorted(({**x,'classes':sorted(x['classes']),'alerts':x['alerts'][:6]} for x in grouped.values()),key=lambda x:x['risk'],reverse=True)
@app.websocket('/ws/alerts')
async def websocket_alerts(ws:WebSocket):
 # Read-only stream, so no write token is required. Origin is checked to stop another site from
 # opening a cross-site WebSocket against the enclave (the classic CSWSH pattern); the stream
 # carries no secrets beyond what /api/alerts already returns.
 origin=ws.headers.get('origin')
 if origin:
  host=ws.headers.get('host')
  allowed={f'http://{host}',f'https://{host}'} if host else set()
  if origin not in allowed: await ws.close(code=1008); return
 await ws.accept(); last=None
 try:
  while True:
   data=store.list(limit=100); signature=data[0]['alert_id'] if data else ''
   if signature!=last: await ws.send_json({'type':'alerts','alerts':data,'summary':store.summary()});last=signature
   await asyncio.sleep(1)
 except WebSocketDisconnect: return
@app.get('/')
def dashboard(): return FileResponse(Path(__file__).parent.parent/'dashboard'/'index.html')
