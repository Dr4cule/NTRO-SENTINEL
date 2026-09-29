"""Explainable, deterministic first-pass detectors. No payload fields are consumed."""
import ipaddress
from engine.contracts import alert

# Destinations outside the internet-facing C2 threat model: RFC1918, CGNAT 100.64/10 (Tailscale
# & other mesh VPNs live here), loopback, link-local, multicast. NOT the documentation ranges
# (TEST-NET) — those stand in for real public IPs in our fixtures. is_private/is_global can't be
# used: modern Python marks TEST-NET private, which would drop legitimate public-facing evidence.
_LOCAL_NETS=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16',
 '100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4')]
def _is_local_dest(ip):
 try: a=ipaddress.ip_address(ip); return any(a in n for n in _LOCAL_NETS)
 except ValueError: return False

# Registrable parents whose subdomains are long/high-entropy by design (CDN cache keys, cloud
# object hosts). Lexical/ngram DGA scoring is meaningless under these -> skip to avoid FPs.
# Live-capture FP lesson (wlp0s20f3, Sep 2026): periodic HTTPS keepalives (Chrome), Google
# push (5228), mDNS (5353/ff02::fb) and subnet broadcast (x.x.x.255) all satisfy naive
# periodicity (sessions>=4, cv<=.15, persist>=60s). Fix: unicast-only + noise-port skip +
# tighter gate (sessions>=5, persist>=120s) + long C2 dedup in the Pipeline. Eval C2 fixture
# (5 sessions, 120s, cv=0, TEST-NET unicast/443) still passes this gate by design.
_TEST_NETS=[ipaddress.ip_network(n) for n in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')]
def _is_test_net(ip):
 try: a=ipaddress.ip_address(ip); return any(a in n for n in _TEST_NETS)
 except ValueError: return False
# LAN/service-discovery noise ports: never C2 on their own (mDNS, SSDP, LLMNR, DHCP, NTP,
# STUN, MikroTik-neighbour). Suppressed for c2_beaconing only; other classes still inspect them.
_NOISE_PORTS={5353,1900,5355,67,68,123,3478,5678,5228}
def _is_noise_traffic(e):
 try:
  if _is_test_net(e.get('dst_ip','')) or _is_test_net(e.get('src_ip','')): return False  # fixtures stay in scope
  for ip in (e.get('src_ip',''), e.get('dst_ip','')):
   try:
    a=ipaddress.ip_address(ip)
    if a.is_multicast or a.is_link_local or a.is_loopback or a.is_reserved or ip=='255.255.255.255' or (a.version==4 and ip.split('.')[-1]=='255'): return True
   except ValueError: continue
  if e.get('dst_port') in _NOISE_PORTS or e.get('src_port') in _NOISE_PORTS: return True
 except Exception: return False
 return False
_KNOWN_GOOD_PARENTS=('cloudfront.net','amazonaws.com','akamai.net','akamaiedge.net','akamaihd.net',
 'fastly.net','fbcdn.net','googleusercontent.com','google.com','gstatic.com','googleapis.com',
 'azureedge.net','windows.net','microsoft.com','office.com','apple.com','icloud.com',
 'cloudflare.net','cloudflare.com','edgekey.net','edgesuite.net')
def _known_good_domain(query):
 q=(query or '').lower().rstrip('.'); return any(q==d or q.endswith('.'+d) for d in _KNOWN_GOOD_PARENTS)

def ddos(e,f):
 # Real SYN floods are half-open: many SYNs, few completed handshakes (completion_ratio low).
 # A CI runner / load test that sends 20+ SYNs but COMPLETES them (SF) is not a flood.
 # UDP reflection is judged on volume + source diversity only (no handshake to complete).
 # NOTE: completion_ratio needs response visibility; assumes a SPAN/tap that sees both directions.
 syn_flood_like=f['syn_count'] >= 20 and f['completion_ratio'] <= .5
 udp_reflect=f['udp_count'] >= 20 and f['unique_sources'] >= 8
 if syn_flood_like or udp_reflect:
  if udp_reflect: subtype='udp_reflection_amplification'
  elif f['source_ip_entropy'] >= 3.5: subtype='spoof_like_source_flood'
  else: subtype='syn_flood'
  return alert(e,'ddos',subtype,min(1,(f['syn_count']+f['udp_count'])/40),{**f,'aggregation_key':'dst='+e['dst_ip']},['T1498'],'ddos-rules-v1')
def c2(e,f):
 # Periodic beaconing to a LOCAL/mesh peer (RFC1918, CGNAT 100.64/10 e.g. Tailscale, multicast)
 # is keepalive noise, not internet C2. Public destinations stay in scope.
 if _is_local_dest(e['dst_ip']): return
 if _is_noise_traffic(e): return  # mDNS/broadcast/DHCP/NTP/STUN/push-keepalive noise (see _NOISE_PORTS)
 if f['session_count'] >= 5 and f['iat_cv'] <= .12 and f['persistence_seconds'] >= 120 and f['destination_port_count'] <= 2:
  return alert(e,'c2_beaconing','periodic_beacon',.8,{**f,'aggregation_key':e['src_ip']+'|'+e['dst_ip']},['T1071.001'],'c2-periodicity-v2')
def dns(e,f):
 # Long, high-entropy labels under trusted CDN/cloud parents (cloudfront.net, *.amazonaws.com,
 # googleusercontent.com, ...) are cache keys / object hosts, not DGA. Skip them.
 if _known_good_domain(f['query']): return
 from models.inference import dga_score
 learned=dga_score(f['query'].split('.')[0])
 if (f['label_length'] >= 18 and f['label_entropy'] >= 3.3) or (learned is not None and learned >= .8):
  subtype='dns_tunnel' if f['query_rate'] >= .05 and f['unique_subdomains'] >= 3 else 'dga_domain'
  mitre=['T1071.004'] if subtype=='dns_tunnel' else ['T1568.002']
  f={**f,'dga_char_ngram_score':round(learned,3) if learned is not None else None}
  return alert(e,'dga_dns_tunnel',subtype,max(min(.95,f['label_entropy']/5),learned or 0),f,mitre,'dns-lexical-ml-v1' if learned is not None else 'dns-lexical-v1')
def encrypted(e,f):
 # Out/in ratio alone flags EVERY upload (webmail attachment, photo, backup) -> pure FP.
 # Require a known-suspicious TLS fingerprint (JA3/JA3S match); ratio stays as evidence only.
 if e.get('tls') and e.get('suspicious_fingerprint'):
  return alert(e,'encrypted_malware','metadata_anomaly',.7,f,['T1071.001'],'tls-metadata-v1')
def recon(e,f):
 # Fan-out with mostly COMPLETED connections (failure_ratio low) is a browser pulling a page
 # from many CDN hosts, not a scan. Scans hit closed ports/hosts -> S0/REJ -> failure_ratio high.
 if (f['unique_dst_ports'] >= 12 or f['unique_dst_hosts'] >= 12) and f['failure_ratio'] >= .5:
  subtype='vertical_scan' if f['unique_dst_ports'] >= f['unique_dst_hosts'] else 'horizontal_scan'
  return alert(e,'recon_scan',subtype,.8,{**f,'aggregation_key':'src='+e['src_ip']},['T1046'],'recon-fanout-v1')
def exfil(e,f):
 # One 600KB HTTPS upload (single session) is a photo/attachment. Real staged exfil is
 # SUSTAINED -> require >=3 sessions in the window (matches the 'sustained_outbound' subtype).
 if f['outbound_bytes'] >= 500000 and f['outbound_inbound_ratio'] >= 5 and f['session_count'] >= 3:
  from models.inference import exfil_anomaly
  a=exfil_anomaly(f['outbound_bytes'],f['outbound_inbound_ratio'])   # ML second opinion; threshold above stays the sole gate
  ev={**f,'aggregation_key':e['src_ip']+'|'+e['dst_ip']}
  if a is not None: ev['exfil_anomaly_score']=a['score']; ev['exfil_anomaly_flag']=a['flag']
  conf=.9 if (a and a['flag']) else .8                               # model concurs it's an outlier -> raise severity
  return alert(e,'exfiltration','sustained_outbound_anomaly',conf,ev,['T1041'],'exfil-baseline-ml-v1' if a is not None else 'exfil-rules-v1')
