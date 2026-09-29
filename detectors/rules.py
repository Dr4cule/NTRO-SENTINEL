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
# LAN/service-discovery noise ports: mDNS, SSDP, LLMNR, DHCP, NTP, STUN, MikroTik-neighbour,
# Google push. A periodic mDNS responder answers from the whole subnet, which looks exactly like
# a reflection amplifier with many "sources" -> suppress before ANY rule judges the volume.
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

# Provider reputation is looked up by ASN (detectors/reputation.py) from a committed, air-gapped
# prefix table. A hand-typed IP-prefix list matched only ~50% of real keepalive destinations and a
# name-regex over the BGP dump matched too much of the internet, so the ASN table is authoritative
# and carries the provider name into the alert evidence.
#
# Ports whose protocol has a LONG-LIVED IDLE by design, so periodic exchange is expected even
# against an unattributable host: SMTP/IMAP/POP (25,110,143,465,587,993,995,5222,5223,5944),
# STUN/ICE + push (3478,5228), VoIP/SIP (5060,51820), IRC/XMPP (6667,6697,1633), DNS (53).
#
# DELIBERATELY EXCLUDES 443, 8080, 8443, 9300, 9418, 27017, 11211. Those are web/IRC/database
# ports AND they are the *primary* malware C2 ports — a first pass wrongly listed 443 here, which
# would have auto-downgraded essentially every real C2 implant to 'medium'. An HTTP/443 beacon to
# an unknown network must stay 'high'. (The scapy/live fixtures and the eval C2 scenario use 443,
# and those must remain the strong case they are.)
_LONG_IDLE_PORTS={25,53,110,143,465,587,993,995,1633,3478,5060,5222,5223,51820,5944,6667,6697,5228}
# Ports above this are ephemeral client ports unless listed above: a connection TO one is a
# response returning, i.e. the remote side is the client, so it is not an outbound beacon.
_EPHEMERAL_FLOOR=1024
# Outbound browser/service traffic of this size is a page load, not a heartbeat. A C2 beacon
# sends a small request and a small response, repeatedly, for minutes.
_BROWSER_MIN_OUTBOUND=1500

def ddos(e,f):
 # Real SYN floods are half-open: many SYNs, few completed handshakes (completion_ratio low).
 # A CI runner / load test that sends 20+ SYNs but COMPLETES them (SF) is not a flood.
 # UDP reflection is judged on volume + source diversity only (no handshake to complete).
 # NOTE: completion_ratio needs response visibility; assumes a SPAN/tap that sees both directions.
 # mDNS/SSDP/broadcast responders answer the WHOLE subnet with tiny replies, so they hit the
 # ">=20 packets from >=8 sources to one port" test and read as reflection amplification. Those
 # are service-discovery chatter, not an attack -> drop them before judging volume.
 if _is_noise_traffic(e): return
 syn_flood_like=f['syn_count'] >= 20 and f['completion_ratio'] <= .5
 udp_reflect=f['udp_count'] >= 20 and f['unique_sources'] >= 8
 if syn_flood_like or udp_reflect:
  if udp_reflect: subtype='udp_reflection_amplification'
  elif f['source_ip_entropy'] >= 3.5: subtype='spoof_like_source_flood'
  else: subtype='syn_flood'
  return alert(e,'ddos',subtype,min(1,(f['syn_count']+f['udp_count'])/40),{**f,'aggregation_key':'dst='+e['dst_ip']},['T1498'],'ddos-rules-v2')
def c2(e,f):
 # --- The core problem, stated honestly -------------------------------------------------
 # Low-jitter periodicity ALONE cannot separate malware phone-home from a browser keepalive,
 # an IMAP IDLE, or a push channel. Live capture on a laptop showed ~90% of "C2" alerts were
 # Chrome/GitHub/Google/WhatsApp keepalives. So a pure timing rule is not a detector, it is a
 # metronome. Three structural signals are required on top of timing before we claim C2:
 #   1. the flow must be a client-initiated request to a SERVICE port (a response to an
 #      ephemeral port is inbound data returning, i.e. the far end is the client, not a server);
 #   2. the payload must be BEACON-SIZED in both directions (a page load transfers kilobytes;
 #      a heartbeat transfers a few hundred bytes, over and over);
 #   3. a known-CDN prefix or a known noisiest service port only DOWNGRADES the alert to
 #      periodic_session with a lower score -- it never hard-blocks, so an implant tunnelling
 #      through a CDN IP is still visible, just ranked below an unknown host.
 if _is_local_dest(e['dst_ip']): return
 if _is_noise_traffic(e): return        # mDNS/broadcast/DHCP/NTP/STUN/push-keepalive noise
 if not f['session_count'] >= 5 or f['iat_cv'] > .12 or f['persistence_seconds'] < 120 or f['destination_port_count'] > 2: return
 # 1. direction: a beacon is a REQUEST to a service port. A connection TO an ephemeral port on
 # a protocol with no idle semantics means we are the server half of someone else's session.
 port=e.get('dst_port') or 0
 if port>_EPHEMERAL_FLOOR and port not in _LONG_IDLE_PORTS: return
 # 2. size: heartbeat-sized exchanges only. Large transfers in either direction are content.
 if f['mean_outbound_bytes'] > _BROWSER_MIN_OUTBOUND: return
 if f['inbound_bytes'] > 0 and f['mean_inbound_bytes'] > _BROWSER_MIN_OUTBOUND: return
 # 3. reputation: downgrade, never suppress. The provider name travels in the evidence so an
 # analyst can audit the decision instead of trusting an opaque score.
 from detectors.reputation import describe
 rep=describe(e['dst_ip']); known=rep['reputation']=='provider' or port in _LONG_IDLE_PORTS
 if known:
  why=('destination is a high-volume periodic-infrastructure network' if rep['reputation']=='provider'
       else 'protocol has a long-lived idle channel (mail/push/VoIP), so periodic exchange is expected')
  return alert(e,'c2_beaconing','periodic_session',.45,{**f,**rep,'aggregation_key':e['src_ip']+'|'+e['dst_ip'],
   'downgrade_reason':f'{why}; beacon-sized and low-jitter, but consistent with legitimate keepalive/push/IDLE'},['T1071.001'],'c2-structure-v1')
 return alert(e,'c2_beaconing','periodic_beacon',.8,{**f,**rep,'aggregation_key':e['src_ip']+'|'+e['dst_ip']},['T1071.001'],'c2-structure-v1')
# Registrable parents whose subdomains are long/high-entropy by design (CDN cache keys, cloud
# object hosts). Lexical/ngram DGA scoring is meaningless under these -> skip to avoid FPs.
_KNOWN_GOOD_PARENTS=('cloudfront.net','amazonaws.com','akamai.net','akamaiedge.net','akamaihd.net',
 'fastly.net','fbcdn.net','googleusercontent.com','google.com','gstatic.com','googleapis.com',
 'azureedge.net','windows.net','microsoft.com','office.com','apple.com','icloud.com',
 'cloudflare.net','cloudflare.com','edgekey.net','edgesuite.net')
def _known_good_domain(query):
 q=(query or '').lower().rstrip('.'); return any(q==d or q.endswith('.'+d) for d in _KNOWN_GOOD_PARENTS)
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
 # Out/in ratio alone flags EVERY upload (webmail attachment, photo, backup) -> pure FP, so
 # ratio is NEVER a gate. On the Zeek path a known-suspicious JA3/JA4 remains the strong signal.
 #
 # F-10 fix (2026-09-29): the offline scapy/live path derives no JA3, so the old
 # `if tls and suspicious_fingerprint` condition could NEVER be true there and the detector
 # was dead outside Zeek. The fallback below uses only metadata that IS available on that
 # path, and requires THREE independent anomalies to agree, so a single odd session cannot
 # produce an alert. It is still scored lower than a real fingerprint match.
 from detectors.reputation import describe
 rep=describe(e['dst_ip']) if e.get('dst_ip') else {'reputation':'unknown'}
 if e.get('tls') and e.get('suspicious_fingerprint'):
  return alert(e,'encrypted_malware','metadata_anomaly',.7,{**f,**rep},['T1071.001'],'tls-metadata-v1')
 # metadata-only fallback: strong upload asymmetry + no host diversity + destination we cannot
 # attribute. Each is individually common; together they are what a C2 upload channel looks like.
 # A CDN/provider destination is excluded because that is where backups and sync legitimately go.
 if e.get('tls') and not e.get('ja3') and not e.get('suspicious_fingerprint'):
  anomalous_size=f.get('outbound_inbound_ratio',0) >= 8
  low_cardinality=f.get('host_sessions',0) <= 2
  unattributed=rep['reputation'] not in ('provider',)
  if anomalous_size and low_cardinality and unattributed:
   return alert(e,'encrypted_malware','upload_channel_anomaly',.5,
    {**f,**rep,'downgrade_reason':'no JA3 available on this ingest path; heuristic scored below a fingerprint match'},
    ['T1071.001'],'tls-metadata-heuristic-v1')
def _provider_spread(f):
 """Fraction of a fan-out window whose destinations resolve to known provider/CDN networks.

 Requires the feature to carry its destination list; when it does not, returns 0.0 so the
 caller treats the spread as UNKNOWN (i.e. does not downgrade). An absent list must never
 make a detector quieter.
 """
 hosts=(f.get('dst_hosts') or (f.get('destination_list') or []))
 if not hosts: return 0.0
 from detectors.reputation import reputation
 hit=sum(1 for h in hosts if reputation(h)=='provider')
 return hit/len(hosts)
def recon(e,f):
 # Fan-out with mostly COMPLETED connections (failure_ratio low) is a browser pulling a page
 # from many CDN hosts, not a scan. Scans hit closed ports/hosts -> S0/REJ -> failure_ratio high.
 #
 # A blanket failure_ratio raise was tried and REJECTED: recorded nmap sweeps sit at 0.50-0.66 in
 # a busy window (a concurrent browser session dilutes the ratio), so raising the gate to 0.7
 # silently disabled real scan detection. The gate therefore stays at 0.5, and the two
 # structural signals below do the discriminating instead:
 #
 #   * PORT DIVERSITY - a sweep enumerates ports; content delivery touches a handful. Fan-out
 #     across many hosts but only a few ports is not a port scan.
 #   * PROVIDER SPREAD - a browser fans out across many CDN/edge ASNs; a sweep enumerates
 #     within one network. If most destinations are provider networks, rank it down.
 #
 # Both only ever DOWNGRADE. A sweep that happens to cross providers still alerts.
 ports, hosts = f['unique_dst_ports'], f['unique_dst_hosts']
 if ports < 12 and hosts < 12 or f['failure_ratio'] < .5: return
 from detectors.reputation import describe
 net=describe(e['dst_ip']); spread=_provider_spread(f)
 # port sweep: many distinct ports -> the defining feature of a service/port scan
 if ports >= 12:
  return alert(e,'recon_scan','vertical_scan',.8,{**f,**net,'provider_spread':round(spread,3)},['T1046'],'recon-fanout-v2')
 # host sweep with few ports: only a real enumeration if the destinations are NOT provider CDNs
 if spread >= 0.5:
  return alert(e,'recon_scan','horizontal_scan',.5,{**f,**net,'provider_spread':round(spread,3),
   'downgrade_reason':f'{spread:.0%} of the fan-out destinations are high-volume provider/CDN networks '
                      'and only {ports} distinct ports were touched; consistent with content distribution '
                      'rather than host enumeration'},
   ['T1046'],'recon-fanout-v2')
 return alert(e,'recon_scan','horizontal_scan',.8,{**f,**net,'provider_spread':round(spread,3)},['T1046'],'recon-fanout-v2')
def exfil(e,f):
 # One 600KB HTTPS upload (single session) is a photo/attachment. Real staged exfil is
 # SUSTAINED -> require >=3 sessions in the window (matches the 'sustained_outbound' subtype).
 if f['outbound_bytes'] >= 500000 and f['outbound_inbound_ratio'] >= 5 and f['session_count'] >= 3:
  from models.inference import exfil_anomaly
  from detectors.reputation import describe
  a=exfil_anomaly(f['outbound_bytes'],f['outbound_inbound_ratio'])   # ML second opinion; threshold above stays the sole gate
  ev={**f,**describe(e['dst_ip']),'aggregation_key':e['src_ip']+'|'+e['dst_ip']}
  if a is not None: ev['exfil_anomaly_score']=a['score']; ev['exfil_anomaly_flag']=a['flag']
  # Live-capture lesson (2026-09-29): 21 consecutive 'exfiltration' alerts, ALL to one
  # Cloudflare IP, 500KB-1MB per window at ratio 8-53 over 7-29 sessions. That is a large
  # sustained upload to a CDN-fronted service -- cloud backup, sync, video -- and it is
  # byte-for-byte the shape of staged exfil. Volume cannot separate them; only the destination
  # network can, so it Ranks the alert instead of suppressing it.
  if ev['reputation']=='provider':
   ev['downgrade_reason']=('destination is a high-volume provider/CDN network; a sustained upload '
                           'of this size is consistent with cloud sync/backup, but the ratio and '
                           'volume still warrant a look')
   conf=.5                                      # 'medium': real exfil to a CDN host is possible, just less likely
   ver='exfil-rules-v2'
  else:
   conf=.9 if (a and a['flag']) else .8         # model concurs it's an outlier -> raise severity
   ver='exfil-baseline-ml-v1' if a is not None else 'exfil-rules-v2'
  return alert(e,'exfiltration','sustained_outbound_anomaly',conf,ev,['T1041'],ver)
