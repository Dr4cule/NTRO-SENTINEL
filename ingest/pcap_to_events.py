"""Offline PCAP -> events adapter (payload-blind), a substitute for the Zeek path.

When Zeek + tcpreplay are unavailable, this assembles L3/L4 headers from a real
.pcap into Zeek-like conn/dns events matching ingest/tailer.py's normalize()
schema, so real capture data can be replayed through the detection Pipeline.

Reads only headers + DNS question names (control-plane metadata, as Zeek's
dns.log does). No packet payload content is inspected; byte counts use L4
payload *lengths* (sizes, not content). Bounded-sample, behavioral (not
label-scored) test harness -- not the sanctioned Tier-A path (see interesting stuff.md).
"""
from __future__ import annotations
import sys
from collections import Counter

PROTO = {6: 'tcp', 17: 'udp', 1: 'icmp'}

def _newflow(ts, proto):
    return {'first': ts, 'last': ts, 'proto': proto, 'orig_bytes': 0, 'resp_bytes': 0,
            'orig_pkts': 0, 'resp_pkts': 0, 'syn': False, 'synack': False, 'rst': False, 'fin': False}

def _key(flows, src, sp, dst, dp, proto):
    fwd = (src, sp, dst, dp, proto)
    if fwd in flows: return fwd, 'orig'
    rev = (dst, dp, src, sp, proto)
    if rev in flows: return rev, 'resp'
    return fwd, 'orig'  # new flow: this packet's src is the originator

def _conn_state(f):
    # Simplified Zeek conn_state: enough to distinguish attempts/scans (S0/REJ) from completed (SF).
    if f['proto'] == 'tcp':
        if not f['synack'] and f['resp_pkts'] == 0:
            return 'REJ' if f['rst'] else 'S0'
        if f['synack'] and (f['fin'] or f['orig_bytes'] or f['resp_bytes']):
            return 'SF'
        return 'RSTO' if f['rst'] else 'OTH'
    return 'SF' if f['resp_pkts'] else 'S0'

def _conn_event(key, f):
    src, sp, dst, dp, proto = key
    return {'ts': f['first'], 'src_ip': src, 'src_port': sp, 'dst_ip': dst, 'dst_port': dp,
            'proto': proto, 'uid': '', 'kind': 'conn', 'orig_bytes': f['orig_bytes'],
            'resp_bytes': f['resp_bytes'], 'conn_state': _conn_state(f),
            'duration': round(f['last'] - f['first'], 6),
            'tcp_flags': 'S' if (f['proto'] == 'tcp' and f['syn']) else ''}  # history[:1], as Zeek

_LAYERS = None
def _layers():
    """Import scapy layers once (kept lazy so --selftest and plain imports don't load scapy)."""
    global _LAYERS
    if _LAYERS is None:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS
        _LAYERS = (PcapReader, IP, IPv6, TCP, UDP, DNS)
    return _LAYERS

def ingest_packet(pkt, flows, dns_out):
    """Fold one packet into the flow table (payload-blind); append any DNS query to dns_out.
    Shared by batch replay (build_events) and live capture (ingest.service.LiveCapture)."""
    _, IP, IPv6, TCP, UDP, DNS = _layers()
    if pkt.haslayer(IP): ip = pkt[IP]; src, dst, pnum = ip.src, ip.dst, ip.proto
    elif pkt.haslayer(IPv6): ip = pkt[IPv6]; src, dst, pnum = ip.src, ip.dst, ip.nh
    else: return
    proto = PROTO.get(pnum, str(pnum)); ts = float(pkt.time)
    if pkt.haslayer(TCP):
        seg = pkt[TCP]; fl = int(seg.flags)
        key, d = _key(flows, src, int(seg.sport), dst, int(seg.dport), proto)
        f = flows.get(key) or flows.setdefault(key, _newflow(ts, proto))
        f['last'] = max(f['last'], ts); plen = len(bytes(seg.payload))
        if d == 'orig':
            f['orig_bytes'] += plen; f['orig_pkts'] += 1
            if (fl & 0x02) and not (fl & 0x10): f['syn'] = True
        else:
            f['resp_bytes'] += plen; f['resp_pkts'] += 1
            if (fl & 0x02) and (fl & 0x10): f['synack'] = True
        if fl & 0x04: f['rst'] = True
        if fl & 0x01: f['fin'] = True
    elif pkt.haslayer(UDP):
        seg = pkt[UDP]; sp, dp = int(seg.sport), int(seg.dport)
        key, d = _key(flows, src, sp, dst, dp, proto)
        f = flows.get(key) or flows.setdefault(key, _newflow(ts, proto))
        f['last'] = max(f['last'], ts); plen = len(bytes(seg.payload))
        if d == 'orig': f['orig_bytes'] += plen; f['orig_pkts'] += 1
        else: f['resp_bytes'] += plen; f['resp_pkts'] += 1
        if (sp == 53 or dp == 53) and pkt.haslayer(DNS):
            try:
                dd = pkt[DNS]
                if dd.qr == 0 and dd.qdcount:
                    qn = dd.qd.qname if not isinstance(dd.qd, list) else dd.qd[0].qname
                    qn = qn.decode('utf-8', 'replace') if isinstance(qn, bytes) else str(qn)
                    dns_out.append({'ts': ts, 'src_ip': src, 'src_port': sp, 'dst_ip': dst,
                        'dst_port': dp, 'proto': 'udp', 'uid': '', 'kind': 'dns',
                        'query': qn.rstrip('.'), 'qtype': '', 'rcode': '', 'answers_count': 0})
            except Exception: pass

def build_events(path, max_packets, progress=200000):
    PcapReader = _layers()[0]
    flows = {}; dns_events = []; seen = 0
    with PcapReader(path) as pr:
        for pkt in pr:
            seen += 1
            if seen > max_packets: break
            if seen % progress == 0: print(f'  parsed {seen} packets, {len(flows)} flows', file=sys.stderr)
            ingest_packet(pkt, flows, dns_events)
    events = [_conn_event(k, f) for k, f in flows.items()] + dns_events
    events.sort(key=lambda e: e['ts'])
    print(f'  built {len(events)} events ({len(flows)} conn, {len(dns_events)} dns) from {seen} packets', file=sys.stderr)
    return events

def run(path, max_packets):
    from engine.stream_consumer import Pipeline
    from time import perf_counter
    t0 = perf_counter(); events = build_events(path, max_packets); parse_s = perf_counter() - t0
    p = Pipeline(); alerts = []; lat = []
    for e in events:
        s = perf_counter(); got = p.process(e); lat.append((perf_counter() - s) * 1000); alerts.extend(got)
    span = (events[-1]['ts'] - events[0]['ts']) if events else 0
    lat.sort(); q = lambda x: round(lat[int((len(lat) - 1) * x)], 4) if lat else None
    by_kind = Counter(e['kind'] for e in events); by_sub = Counter((a['threat_class'], a['subtype']) for a in alerts)
    print('\n=== PCAP replay through detection Pipeline (offline, payload-blind) ===')
    print(f'events: {len(events)}  {dict(by_kind)}   capture span: {span:.1f}s   parse: {parse_s:.1f}s')
    print(f'detector step p50/p95/p99 ms (single-thread, offline): {q(.5)}/{q(.95)}/{q(.99)}')
    print(f'alerts: {len(alerts)}   by class: {dict(Counter(a["threat_class"] for a in alerts))}')
    for (c, sub), n in by_sub.most_common():
        print(f'   {c}/{sub}: {n}')
    print('\nsample alerts:')
    for a in alerts[:10]:
        ev = a['supporting_evidence']
        print(f"  [{a['severity']}] {a['threat_class']}/{a['subtype']} conf={a['confidence']} "
              f"{a['flow_id']['src_ip']}->{a['flow_id']['dst_ip']} agg={ev.get('aggregation_key', '')}")
    return alerts

def _selftest():
    assert _conn_state({'proto': 'tcp', 'synack': False, 'resp_pkts': 0, 'rst': False, 'orig_bytes': 0, 'resp_bytes': 0, 'fin': False}) == 'S0'
    assert _conn_state({'proto': 'tcp', 'synack': False, 'resp_pkts': 0, 'rst': True, 'orig_bytes': 0, 'resp_bytes': 0, 'fin': False}) == 'REJ'
    assert _conn_state({'proto': 'tcp', 'synack': True, 'resp_pkts': 2, 'rst': False, 'orig_bytes': 10, 'resp_bytes': 20, 'fin': True}) == 'SF'
    assert _conn_state({'proto': 'udp', 'resp_pkts': 0}) == 'S0' and _conn_state({'proto': 'udp', 'resp_pkts': 3}) == 'SF'
    e = _conn_event(('1.1.1.1', 5, '2.2.2.2', 80, 'tcp'), {'first': 1.0, 'last': 2.5, 'proto': 'tcp', 'orig_bytes': 100,
        'resp_bytes': 0, 'orig_pkts': 1, 'resp_pkts': 0, 'syn': True, 'synack': False, 'rst': False, 'fin': False})
    assert e['tcp_flags'] == 'S' and e['conn_state'] == 'S0' and e['kind'] == 'conn' and e['duration'] == 1.5
    print('selftest OK')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest': _selftest(); sys.exit(0)
    if len(sys.argv) < 2:
        print('usage: python -m ingest.pcap_to_events <pcap> [max_packets]', file=sys.stderr); sys.exit(2)
    run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 500000)


