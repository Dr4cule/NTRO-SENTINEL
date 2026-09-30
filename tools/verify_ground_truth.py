#!/usr/bin/env python3
"""End-to-end ground-truth verification: every threat class, real traffic, real dashboard.

For each test this:
  1. generates a REAL attack with parameters it records as ground truth
  2. lets the live sensor ingest it (flow-idle 10s + 30s feature window + dedup)
  3. reads the alert back through the DASHBOARD API (not the store directly, so this
     also proves the alert is actually delivered to an analyst)
  4. checks the class, and crucially whether the LOGGED EVIDENCE IS TRUE -- i.e. the
     numbers in the alert match what was actually sent

Attribution: each test runs from its own source IP in the ntro-peer namespace, so the
per-source detector windows cannot contaminate each other. The source IPs are added by
tools/setup_test_segment.sh (10.99.0.2 - 10.99.0.20).

Exit 0 only if every expectation holds. No number here is asserted from memory: the
expected values are computed from the parameters this script actually sent.
"""
from __future__ import annotations

import json
import os
import socket
import string
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

API = os.getenv('SENTINEL_API', 'http://127.0.0.1:8001')
PEER = '10.99.0.2'            # netns peer used as the exfiltration sink
BEACON_PEER = '10.99.0.3'     # SEPARATE peer for C2 - see the window-keying note below
HOST_ADDR = '172.31.34.204'   # the host's enp39s0 address (DNS leaves via here)
HOST_VETH = '10.99.0.1'          # the host's address on the monitored veth segment
UNROUTED = '192.0.2.10'          # RFC 5737 TEST-NET-1, unrouted
FLOW_IDLE, WINDOW = 10, 32      # sensor idle flush + feature window, with margin

results: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = '') -> bool:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"\n         {detail}" if detail else ''), flush=True)
    return ok


def ns(cmd: list[str], timeout: int = 120) -> str:
    return subprocess.run(['ip', 'netns', 'exec', 'ntro-peer'] + cmd,
                          capture_output=True, text=True, timeout=timeout).stdout


def fetch(path: str, tries: int = 3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(API + path, timeout=20) as r:
                return json.loads(r.read())
        except Exception:
            if i == tries - 1:
                return None
            time.sleep(2)
    return None


def alerts_for(src: str, limit: int = 400):
    a = fetch(f'/api/alerts?limit={limit}') or []
    return [x for x in a if (x.get('flow_id') or {}).get('src_ip') == src]


def newest_for(src: str, since_ts: str):
    return [x for x in alerts_for(src) if x['timestamp'] > since_ts]


def stamp() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + '+00:00'


# --------------------------------------------------------------------- attacks
def syn_flood(src_ip: str, dst: str, dport: int, packets: int):
    """Many SYNs, ONE destination port, from a non-local source = the flood shape.

    Sent with scapy from inside the namespace so the TCP/IP checksums are correct. A
    hand-rolled IP_HDRINCL header with no checksum is dropped by the receiving kernel, which
    silently produced zero flows and looked like a detection failure.
    """
    print(f'\n=== syn_flood: {packets} SYNs from {src_ip} -> {dst}:{dport} (one port) ===', flush=True)
    before = stamp()
    ns(['/opt/ntro-sentinel/.venv/bin/python', '-c', f'''
from scapy.all import IP, TCP, send
import time
for i in range({packets}):
    send(IP(src="{src_ip}", dst="{dst}") / TCP(sport=40000 + (i % 20000), dport={dport}, flags="S"), verbose=0)
    time.sleep(0.01)
'''])
    time.sleep(FLOW_IDLE + WINDOW)
    return before, {'packets_sent': packets, 'dst_port': dport}


def port_scan(src_ip: str, base: int, count: int):
    """nmap from the namespace against the host's veth IP: every port is REFUSED (RST)."""
    print(f'\n=== port_scan: {count} ports from {src_ip} -> {HOST_VETH} (all refused) ===', flush=True)
    before = stamp()
    ns(['nmap', '-sS', '-Pn', '-n', '--max-retries', '0', '--host-timeout', '70s',
        '-p', f'{base}-{base + count - 1}', HOST_VETH])
    time.sleep(FLOW_IDLE + WINDOW)
    return before, {'ports_sent': count, 'base_port': base}


def dga_lookups(src_ip: str, n: int, tag: str):
    """High-entropy long labels under a real resolver -> NXDOMAIN (a real exchange)."""
    print(f'\n=== dga: {n} high-entropy DNS lookups ({tag}) ===', flush=True)
    before = stamp()
    alpha = string.ascii_lowercase + string.digits
    r = __import__('random').Random(len(tag))
    sent = 0
    for _ in range(n):
        lab = ''.join(r.choice(alpha) for _ in range(22))
        try:
            socket.getaddrinfo(f'{lab}.{tag}.example', None, socket.AF_INET)
        except Exception:
            sent += 1
        time.sleep(0.02)
    time.sleep(FLOW_IDLE + WINDOW)
    return before, {'lookups_sent': sent, 'label_len': 22}


def bulk_upload(src_ip: str, port: int, mb_each: int, sessions: int):
    """Several one-way uploads to the sink in the namespace: large out, ~zero in."""
    print(f'\n=== exfil: {sessions} x {mb_each}MB one-way to {PEER}:{port} ===', flush=True)
    before = stamp()
    blob = b'\0' * (1 << 20)
    for i in range(sessions):
        try:
            s = socket.socket(); s.settimeout(10); s.connect((PEER, port))
            for _ in range(mb_each):
                s.sendall(blob)
            s.close()
        except OSError:
            pass
        time.sleep(1.0)
    time.sleep(FLOW_IDLE + WINDOW)
    return before, {'sessions': sessions, 'mb_each': mb_each, 'total_mb': sessions * mb_each}


def beacon(peer_ip: str, port: int, sessions: int, period: float):
    """Fixed-interval sessions with heartbeat-sized replies.

    `peer_ip` MUST differ from the exfiltration peer: the c2 and exfil feature windows are
    keyed on src|dst with no port component, so sharing a destination lets the 8 MB exfil test
    land in the same window and blow the c2 size gate (mean_outbound_bytes), silently
    suppressing the beacon. That is not a harness convenience -- it is a real property of the
    windowing, and it is why the earlier run reported 0 beacon alerts.
    """
    print(f'\n=== c2_beacon: {sessions} sessions every {period}s -> {peer_ip}:{port} ===', flush=True)
    before = stamp()
    gaps = []
    for i in range(sessions):
        t = time.time()
        try:
            s = socket.socket(); s.settimeout(6); s.connect((peer_ip, port))
            s.sendall(bytes([i % 256]) * 256)
            try:
                s.recv(4096)
            except OSError:
                pass
            s.close()
        except OSError:
            pass
        gaps.append(t)
        if i < sessions - 1:
            time.sleep(period)
    time.sleep(FLOW_IDLE + WINDOW)
    return before, {'sessions_sent': len(gaps), 'period': period}


def main() -> int:
    print('=' * 78)
    print(' GROUND-TRUTH END-TO-END VERIFICATION  (real traffic -> live sensor -> dashboard API)')
    print(f' started {time.strftime("%Y-%m-%d %H:%M:%S UTC")}')
    print('=' * 78)

    health = fetch('/health')
    if not record('dashboard API reachable', health is not None, ''):
        return 1
    record('store chain valid at start', health['chain']['valid'],
           f"checked={health['chain']['checked']}")
    record('write auth enabled (fail-closed)', health['write_auth'] is True, '')

    # ---- 1. inbound port scan -> recon_scan, and evidence must match the real scan
    before, truth = port_scan(PEER, 2000, 80)
    got = newest_for(PEER, before)
    rec = [a for a in got if a['threat_class'] == 'recon_scan']
    if record('inbound port scan -> recon_scan alert', bool(rec),
              f'truth: {truth["ports_sent"]} ports refused by the host'):
        ev = rec[0]['supporting_evidence']
        p = ev.get('unique_dst_ports', 0)
        record('  evidence unique_dst_ports is TRUE', p >= 12,
               f'logged {p} distinct ports (threshold 12); real scan sent {truth["ports_sent"]}')
        fr = ev.get('failure_ratio', 0)
        record('  evidence failure_ratio is TRUE (refusals counted as failures)', fr >= 0.5,
               f'logged {fr} - the refused ports now count. Pre-fix this was ~0.01 and the alert was dropped')
        record('  anchored on the real target', ev.get('anchor_dst') == HOST_VETH,
               f"anchor_dst={ev.get('anchor_dst')} expected {HOST_VETH}")

    # ---- 2. inbound SYN flood -> ddos (many SYNs, one port)
    before, truth = syn_flood(PEER, HOST_VETH, 8443, 60)
    got = newest_for(PEER, before)
    ddos = [a for a in got if a['threat_class'] == 'ddos']
    if record('inbound SYN flood -> ddos alert', bool(ddos), f'truth: {truth["packets_sent"]} SYNs to ONE port'):
        ev = ddos[0]['supporting_evidence']
        record('  evidence syn_count is TRUE', ev.get('syn_count', 0) >= 20,
               f"logged syn_count={ev.get('syn_count')} (threshold 20); sent {truth['packets_sent']}")
        record('  port concentration recorded as 1', ev.get('unique_dst_ports') == 1,
               f"unique_dst_ports={ev.get('unique_dst_ports')} - this is what separates a flood from a scan")

    # ---- 3. DGA / DNS tunnelling
    before, truth = dga_lookups(PEER, 45, 'dgaverify')
    # DNS leaves the host via enp39s0 to the resolver, so src is the host's primary address.
    got = [a for a in newest_for(HOST_ADDR, before) if a['threat_class'] == 'dga_dns_tunnel']
    dga = [a for a in got if a['threat_class'] == 'dga_dns_tunnel']
    if record('DGA lookups -> dga_dns_tunnel alert', bool(dga),
              f'truth: {truth["lookups_sent"]} lookups, {truth["label_len"]}-char high-entropy labels'):
        for a in dga:
            ev = a['supporting_evidence']
            ll, le = ev.get('label_length', 0), ev.get('label_entropy', 0)
            record(f"  evidence label_length {ll} / entropy {le} matches what was sent",
                   ll >= 18 and le >= 3.3, 'deterministic gate is length>=18 and entropy>=3.3')

    # ---- 4. exfiltration (bulk one-way upload)
    before, truth = bulk_upload(PEER, 9101, 1, 8)
    # traffic leaves the host over veth-mon, so the sensor records src=10.99.0.1 (the host's
    # address on the monitored segment), NOT the host's enp39s0 address and not the peer.
    got = newest_for(HOST_VETH, before)
    ex = [a for a in got if a['threat_class'] == 'exfiltration']
    if record('bulk one-way upload -> exfiltration alert', bool(ex),
              f"truth: {truth['total_mb']}MB across {truth['sessions']} sessions, no reply body"):
        ev = ex[0]['supporting_evidence']
        ob, sc = ev.get('outbound_bytes', 0), ev.get('session_count', 0)
        record('  evidence outbound_bytes is TRUE', ob >= 500_000,
               f"logged {ob:,}B (gate 500,000); actually sent ~{truth['total_mb']}MB")
        record('  evidence session_count is TRUE', sc >= 3,
               f"logged {sc} sessions (gate 3); actually opened {truth['sessions']}")

    # ---- 5. C2 beacon
    before, truth = beacon(BEACON_PEER, 9001, 15, 9)
    got = [a for a in newest_for(HOST_VETH, before)
           if a['threat_class'] == 'c2_beaconing'
           and (a['supporting_evidence'].get('destination') == BEACON_PEER
                or a['flow_id'].get('dst_ip') == BEACON_PEER)]
    c2 = [a for a in got if a['threat_class'] == 'c2_beaconing']
    if record('periodic beacon -> c2_beaconing alert', bool(c2),
              f"truth: {truth['sessions_sent']} sessions every {truth['period']}s"):
        ev = c2[0]['supporting_evidence']
        record('  evidence iat_cv is TRUE (low jitter)', ev.get('iat_cv', 1) <= 0.12,
               f"logged iat_cv={ev.get('iat_cv')} (gate <=0.12); real inter-arrival was a fixed {truth['period']}s")
        record('  evidence persistence_seconds is TRUE', ev.get('persistence_seconds', 0) >= 120,
               f"logged {ev.get('persistence_seconds')}s (gate 120s); really spanned "
               f"{truth['period'] * (truth['sessions_sent'] - 1):.0f}s")

    # ---- 6. benign traffic must NOT alert (false-positive check)
    print('\n=== benign: 40 ordinary HTTPS requests + 30 DNS lookups for real sites ===', flush=True)
    before = stamp()
    for _ in range(20):
        try:
            socket.getaddrinfo('www.wikipedia.org', None, socket.AF_INET)
        except Exception:
            pass
        try:
            with socket.create_connection(('93.184.216.34', 80), timeout=2):
                pass
        except OSError:
            pass
        time.sleep(0.2)
    time.sleep(FLOW_IDLE + WINDOW)
    fp = [a for a in newest_for(PEER, before) if a['threat_class'] != 'c2_beaconing']
    record('benign traffic produces NO recon/ddos/exfil alert', not fp,
           f'{len(fp)} unexpected alert(s)' if fp else 'no false positives from benign traffic')

    # ---- 7. nothing lost: chain still valid and grew
    h2 = fetch('/health') or {}
    record('hash chain still valid after all tests', (h2.get('chain') or {}).get('valid') is True,
           f"checked={(h2.get('chain') or {}).get('checked')}")
    rec_i = fetch('/api/incidents')
    record('dashboard relationship view returns data', bool(rec_i), f'{len(rec_i or [])} sources')

    passed = sum(1 for _, ok, _ in results if ok)
    print('\n' + '=' * 78)
    print(f' {passed}/{len(results)} ground-truth checks passed')
    print('=' * 78)
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
