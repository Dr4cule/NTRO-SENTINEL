"""Explainable, deterministic first-pass detectors. No payload fields are consumed."""
from engine.contracts import alert

def ddos(e,f):
 if f['syn_count'] >= 20 or (f['udp_count'] >= 20 and f['unique_sources'] >= 8):
  # A one-directional monitor may see only reflector->victim packets, so reverse
  # byte evidence can be unavailable. UDP volume plus reflector-source diversity
  # remains valid passive topology evidence in that observation direction.
  if f['udp_count'] >= 20 and f['unique_sources'] >= 8: subtype='udp_reflection_amplification'
  elif f['source_ip_entropy'] >= 3.5: subtype='spoof_like_source_flood'
  else: subtype='syn_flood'
  return alert(e,'ddos',subtype,min(1,(f['syn_count']+f['udp_count'])/40),{**f,'aggregation_key':'dst='+e['dst_ip']},['T1498'],'ddos-rules-v1')
def c2(e,f):
 if f['session_count'] >= 4 and f['iat_cv'] <= .15 and f['persistence_seconds'] >= 60 and f['destination_port_count'] <= 2:
  return alert(e,'c2_beaconing','periodic_beacon',.8,{**f,'aggregation_key':e['src_ip']+'|'+e['dst_ip']},['T1071.001'],'c2-periodicity-v1')
def dns(e,f):
 from models.inference import dga_score
 learned=dga_score(f['query'].split('.')[0])
 if (f['label_length'] >= 18 and f['label_entropy'] >= 3.3) or (learned is not None and learned >= .8):
  subtype='dns_tunnel' if f['query_rate'] >= .05 and f['unique_subdomains'] >= 3 else 'dga_domain'
  mitre=['T1071.004'] if subtype=='dns_tunnel' else ['T1568.002']
  f={**f,'dga_char_ngram_score':round(learned,3) if learned is not None else None}
  return alert(e,'dga_dns_tunnel',subtype,max(min(.95,f['label_entropy']/5),learned or 0),f,mitre,'dns-lexical-ml-v1' if learned is not None else 'dns-lexical-v1')
def encrypted(e,f):
 if e.get('tls') and (f['outbound_inbound_ratio'] > 8 or e.get('suspicious_fingerprint')):
  return alert(e,'encrypted_malware','metadata_anomaly',.7,f,['T1071.001'],'tls-metadata-v1')
def recon(e,f):
 if f['unique_dst_ports'] >= 12 or f['unique_dst_hosts'] >= 12:
  subtype='vertical_scan' if f['unique_dst_ports'] >= f['unique_dst_hosts'] else 'horizontal_scan'
  return alert(e,'recon_scan',subtype,.8,{**f,'aggregation_key':'src='+e['src_ip']},['T1046'],'recon-fanout-v1')
def exfil(e,f):
 if f['outbound_bytes'] >= 500000 and f['outbound_inbound_ratio'] >= 5:
  from models.inference import exfil_anomaly
  a=exfil_anomaly(f['outbound_bytes'],f['outbound_inbound_ratio'])   # ML second opinion; threshold above stays the sole gate
  ev={**f,'aggregation_key':e['src_ip']+'|'+e['dst_ip']}
  if a is not None: ev['exfil_anomaly_score']=a['score']; ev['exfil_anomaly_flag']=a['flag']
  conf=.9 if (a and a['flag']) else .8                               # model concurs it's an outlier -> raise severity
  return alert(e,'exfiltration','sustained_outbound_anomaly',conf,ev,['T1041'],'exfil-baseline-ml-v1' if a is not None else 'exfil-rules-v1')
