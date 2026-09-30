"""Local append-only forensic alert store with a tamper-evident hash chain."""
from __future__ import annotations
import hashlib, json, os, sqlite3, time
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path

class AlertStore:
 def __init__(self,path=None):
  # Resolve ALERT_DB at construction, not at import: a default argument would freeze the
  # value the first time this module is imported, so anything that sets the env var later
  # (tests, a re-pointed deployment) would silently keep writing to the old file.
  self.path=path or os.getenv('ALERT_DB','artifacts/sentinel.db'); Path(self.path).parent.mkdir(parents=True,exist_ok=True); self._init()
 def _connect(self):
  con=sqlite3.connect(self.path,timeout=30.0); con.row_factory=sqlite3.Row; con.isolation_level=None
  con.execute('PRAGMA journal_mode=WAL'); con.execute('PRAGMA busy_timeout=30000'); con.execute('PRAGMA synchronous=NORMAL'); return con

 def _begin_immediate(self,con,attempts=60):
  """Take the write lock up front, retrying while another writer holds it.

  BEGIN IMMEDIATE makes the read of the chain head and the insert that extends it atomic
  against every other process. Without it sqlite3 runs the SELECT in autocommit (no lock
  held), then opens the write transaction only at the INSERT — so two writers (e.g. the
  live-capture consumer and a concurrent API upload) can read the SAME head and both chain
  from it, silently forking the chain and failing verify_chain()."""
  for i in range(attempts):
   try: con.execute('BEGIN IMMEDIATE'); return True
   except sqlite3.OperationalError:
    if i==attempts-1: raise
    time.sleep(0.25)
 def _init(self):
  with closing(self._connect()) as con:
   con.executescript('''CREATE TABLE IF NOT EXISTS alerts (seq INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT UNIQUE NOT NULL,timestamp TEXT NOT NULL,threat_class TEXT NOT NULL,severity TEXT NOT NULL,confidence REAL NOT NULL,src_ip TEXT,dst_ip TEXT,record_json TEXT NOT NULL,prev_hash TEXT NOT NULL,record_hash TEXT NOT NULL);
   CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(timestamp DESC); CREATE INDEX IF NOT EXISTS idx_alert_class ON alerts(threat_class);
   CREATE TABLE IF NOT EXISTS telemetry_metrics (metric_ts TEXT NOT NULL,events_total INTEGER NOT NULL,alerts_total INTEGER NOT NULL,stream_lag INTEGER NOT NULL,p95_latency_ms REAL,throughput_eps REAL);'''); con.commit()
 def append(self,record):
  canonical=json.dumps(record,sort_keys=True,separators=(',',':'))
  with closing(self._connect()) as con:
   self._begin_immediate(con)
   try:
    row=con.execute('SELECT record_hash FROM alerts ORDER BY seq DESC LIMIT 1').fetchone(); previous=row['record_hash'] if row else '0'*64; digest=hashlib.sha256((previous+canonical).encode()).hexdigest()
    con.execute('INSERT INTO alerts (alert_id,timestamp,threat_class,severity,confidence,src_ip,dst_ip,record_json,prev_hash,record_hash) VALUES (?,?,?,?,?,?,?,?,?,?)',(record['alert_id'],record['timestamp'],record['threat_class'],record['severity'],record['confidence'],record['flow_id']['src_ip'],record['flow_id']['dst_ip'],canonical,previous,digest))
    seq=con.execute('SELECT MAX(seq) FROM alerts').fetchone()[0]
    con.execute('COMMIT')
   except sqlite3.IntegrityError:
    con.execute('ROLLBACK'); return False
  self._write_anchor(seq,digest)   # outside the txn; see verify_chain
  return True
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
  out={'valid':True,'checked':checked,'head_hash':previous}
  # F24: the chain alone cannot see a TAIL deletion. verify_chain walks the rows that are still
  # present, so removing the newest record leaves an internally consistent prefix and it reports
  # valid. Comparing the recomputed head against an anchor written at the time of appending is
  # what actually detects it.
  anchor=self._read_anchor()
  if anchor:
   out['anchored']=True
   out['anchor_count']=anchor.get('count')
   out['anchor_head_hash']=anchor.get('head_hash')
   if anchor.get('count')!=checked or anchor.get('head_hash')!=previous:
    out['valid']=False
    out['failure']='anchor_mismatch'
    out['detail']=(f"anchored head {str(anchor.get('head_hash'))[:16]}... over {anchor.get('count')} records "
                   f"but the store now holds {checked} with head {previous[:16]}... "
                   "(tail deletion, truncation or a rewritten database)")
  else:
   out['anchored']=False
  return out
 def _anchor_path(self):
  return Path(self.path+'.anchor')
 def _read_anchor(self):
  try:
   p=self._anchor_path()
   return json.loads(p.read_text()) if p.is_file() else None
  except Exception: return None
 def _write_anchor(self,count,head_hash):
  """Persist the head hash OUTSIDE the database, so a party who can rewrite the database cannot
  silently agree with itself. Best effort: a read-only or foreign-owned directory must not stop
  alerts being stored, it only means the store is unanchored and says so."""
  try:
   tmp=self._anchor_path().with_suffix('.tmp')
   tmp.write_text(json.dumps({'count':count,'head_hash':head_hash,'updated_at':datetime.now(timezone.utc).isoformat()}))
   tmp.replace(self._anchor_path())
  except Exception: pass
 def metric(self,**d):
  with closing(self._connect()) as con:
   self._begin_immediate(con)
   try:
    con.execute('INSERT INTO telemetry_metrics VALUES(?,?,?,?,?,?)',(d['metric_ts'],d['events_total'],d['alerts_total'],d.get('stream_lag',0),d.get('p95_latency_ms'),d.get('throughput_eps',0))); con.execute('COMMIT')
   except sqlite3.IntegrityError: con.execute('ROLLBACK')

JsonlAlertStore=AlertStore
