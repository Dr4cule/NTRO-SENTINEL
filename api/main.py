"""Sentinel API and live dashboard delivery surface."""
from __future__ import annotations
import asyncio
from pathlib import Path
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from alertstore.store import AlertStore

app=FastAPI(title='NTRO Sentinel',version='1.0.0',description='Passive, payload-blind threat intelligence')
store=AlertStore()
class IncomingAlert(BaseModel):
 alert_id:str; timestamp:str; flow_id:dict; threat_class:str; subtype:str; confidence:float; severity:str; supporting_evidence:dict; mitre_attack:list[str]; model_version:str
@app.get('/health')
def health(): return {'status':'ok','version':app.version,'store':'sqlite','chain':store.verify_chain(),'pipeline':store.summary()['pipeline']}
@app.get('/api/alerts')
def alerts(threat_class:str|None=None,severity:str|None=None,limit:int=Query(250,ge=1,le=1000)): return store.list(threat_class,severity,limit)
@app.post('/api/alerts',status_code=201)
def add_alert(item:IncomingAlert): return {'created':store.append(item.model_dump())}
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
 await ws.accept(); last=None
 try:
  while True:
   data=store.list(limit=100); signature=data[0]['alert_id'] if data else ''
   if signature!=last: await ws.send_json({'type':'alerts','alerts':data,'summary':store.summary()});last=signature
   await asyncio.sleep(1)
 except WebSocketDisconnect: return
@app.get('/')
def dashboard(): return FileResponse(Path(__file__).parent.parent/'dashboard'/'index.html')
