#!/usr/bin/env python3
"""READ-ONLY probe: does the live path turn an inbound external scan into a recon alert?

Writes nothing to the store and touches no service. It sniffs enp39s0 with the SAME
LiveCapture + Pipeline the service uses, and reports what the recon feature window
actually accumulates for EXTERNAL source IPs. Use this to tell apart:
  (a) traffic never arrives          -> external sources never appear
  (b) traffic arrives, no flows      -> flow finalisation is dropping them
  (c) flows arrive, window fills     -> detector gating is rejecting them
"""
import sys, time, collections
sys.path.insert(0, '/opt/ntro-sentinel')

from scapy.all import AsyncSniffer
from engine.stream_consumer import Pipeline
from ingest.pcap_to_events import ingest_packet, _conn_event

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 90
LOCAL = ('172.31.34.204', '10.99.', '10.0.', '192.168.', '127.', '169.254.')

flows = {}          # same shape LiveCapture uses
pipeline = Pipeline()
dns_out = []
flow_events = collections.Counter()   # source bucket -> n conn events
alerts = []
dnsq = collections.Counter()


def external(sip):
    return not sip.startswith(LOCAL)


def on_pkt(pkt):
    ingest_packet(pkt, flows, dns_out)
    for d in dns_out:
        dnsq[d.get('src_ip')] += 1
    dns_out.clear()


def is_local(sip):
    return sip.startswith(LOCAL)


sn = AsyncSniffer(iface='enp39s0', prn=on_pkt, store=False)
sn.start()
print(f'sniffing enp39s0 for {SECONDS}s — run `nmap <your-ip>` from your laptop NOW', flush=True)

end = time.time() + SECONDS
last_flush = 0.0
while time.time() < end:
    time.sleep(0.5)
    now = time.time()
    if now - last_flush >= 5:          # same 10s->5s cadence the service uses
        last_flush = now
        due = [k for k, f in flows.items() if now - f['last'] >= 5]
        for k in due:
            e = _conn_event(k, flows.pop(k))
            if not is_local(e.get('src_ip', '')):
                flow_events[e['src_ip']] += 1
            got = pipeline.process(e)
            for a in got:
                alerts.append(a)

sn.stop()
ext_flows = {s: n for s, n in flow_events.items() if not is_local(s)}
print(f'\n--- after {SECONDS}s ---')
print(f'open flows still buffering : {len(flows)}')
print(f'EXTERNAL conn events emitted: {sum(ext_flows.values())}')
for s, n in sorted(ext_flows.items(), key=lambda kv: -kv[1])[:10]:
    print(f'    {s:<18} {n} flow events')
print(f'\nalerts produced: {len(alerts)}')
for a in alerts:
    f = a['flow_id']
    print(f"    {a['threat_class']}/{a['subtype']}  {f.get('src_ip')} -> {f.get('dst_ip')}  conf={a['confidence']}")
if not ext_flows:
    print('\nDIAGNOSIS: (a) no external flows finalised — inbound scans are not becoming conn events')
elif not any(a['threat_class'] == 'recon_scan' for a in alerts):
    print('\nDIAGNOSIS: (c) external flows arrived but no recon alert — detector gating rejected them')
else:
    print('\nDIAGNOSIS: recon alerts ARE produced from live external traffic')
