"""Local append-only forensic alert store with a tamper-evident hash chain."""
from __future__ import annotations
import hashlib, json, os, sqlite3
from contextlib import closing
from pathlib import Path

class AlertStore:
 def __init__(self,path=os.getenv('ALERT_DB','artifacts/sentinel.db')):
  self.path=path; Path(path).parent.mkdir(parents=True,exist_ok=True); self._init()
 def _connect(self):
  con=sqlite3.connect(self.path); con.row_factory=sqlite3.Row
  con.execute('PRAGMA journal_mode=WAL'); con.execute('PRAGMA busy_timeout=5000'); return con
 def _init(self):
  with closing(self._connect()) as con:
   con.executescript('''CREATE TABLE IF NOT EXISTS alerts (seq INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT UNIQUE NOT NULL,timestamp TEXT NOT NULL,threat_class TEXT NOT NULL,severity TEXT NOT NULL,confidence REAL NOT NULL,src_ip TEXT,dst_ip TEXT,record_json TEXT NOT NULL,prev_hash TEXT NOT NULL,record_hash TEXT NOT NULL);
   CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(timestamp DESC); CREATE INDEX IF NOT EXISTS idx_alert_class ON alerts(threat_class);
   CREATE TABLE IF NOT EXISTS telemetry_metrics (metric_ts TEXT NOT NULL,events_total INTEGER NOT NULL,alerts_total INTEGER NOT NULL,stream_lag INTEGER NOT NULL,p95_latency_ms REAL,throughput_eps REAL);'''); con.commit()
 def append(self,record):
  canonical=json.dumps(record,sort_keys=True,separators=(',',':'))
  with closing(self._connect()) as con:
   row=con.execute('SELECT record_hash FROM alerts ORDER BY seq DESC LIMIT 1').fetchone(); previous=row['record_hash'] if row else '0'*64; digest=hashlib.sha256((previous+canonical).encode()).hexdigest()
   try:
    con.execute('INSERT INTO alerts (alert_id,timestamp,threat_class,severity,confidence,src_ip,dst_ip,record_json,prev_hash,record_hash) VALUES (?,?,?,?,?,?,?,?,?,?)',(record['alert_id'],record['timestamp'],record['threat_class'],record['severity'],record['confidence'],record['flow_id']['src_ip'],record['flow_id']['dst_ip'],canonical,previous,digest)); con.commit(); return True
   except sqlite3.IntegrityError: return False
 def list(self,threat_class=None,severity=None,limit=250):
  sql='SELECT record_json FROM alerts WHERE 1=1'; values=[]
  if threat_class: sql+=' AND threat_class=?'; values.append(threat_class)
  if severity: sql+=' AND severity=?'; values.append(severity)
  sql+=' ORDER BY seq DESC LIMIT ?'; values.append(min(max(limit,1),1000))
  with closing(self._connect()) as con:return [json.loads(x['record_json']) for x in con.execute(sql,values)]
 def summary(self):
  with closing(self._connect()) as con:
   total=con.execute('SELECT COUNT(*) c FROM alerts').fetchone()['c']; classes={r['threat_class']:r['c'] for r in con.execute('SELECT threat_class,COUNT(*) c FROM alerts GROUP BY threat_class')}; severities={r['severity']:r['c'] for r in con.execute('SELECT severity,COUNT(*) c FROM alerts GROUP BY severity')}; latest=con.execute('SELECT * FROM telemetry_metrics ORDER BY rowid DESC LIMIT 1').fetchone()
  return {'total_alerts':total,'by_class':classes,'by_severity':severities,'pipeline':dict(latest) if latest else {'events_total':0,'alerts_total':0,'stream_lag':0,'p95_latency_ms':None,'throughput_eps':0}}
 def verify_chain(self):
  previous='0'*64; checked=0
  with closing(self._connect()) as con:
   for row in con.execute('SELECT * FROM alerts ORDER BY seq'):
    actual=hashlib.sha256((previous+row['record_json']).encode()).hexdigest()
    if row['prev_hash']!=previous or row['record_hash']!=actual:return {'valid':False,'checked':checked,'failed_sequence':row['seq']}
    previous=actual; checked+=1
  return {'valid':True,'checked':checked,'head_hash':previous}
 def metric(self,**d):
  with closing(self._connect()) as con: con.execute('INSERT INTO telemetry_metrics VALUES(?,?,?,?,?,?)',(d['metric_ts'],d['events_total'],d['alerts_total'],d.get('stream_lag',0),d.get('p95_latency_ms'),d.get('throughput_eps',0)));con.commit()

JsonlAlertStore=AlertStore
