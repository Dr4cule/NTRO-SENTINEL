"""Focused SYN burst at a single port -> the DDoS shape the detector should still catch.

Deliberately the complement of a port scan: many SYNs, ONE destination port, no completed
handshakes (unrouted). Targets 192.0.2.0/24 (RFC 5737 TEST-NET-1) so nothing real is touched.
Sends a few dozen packets total.

Usage: sudo python tools/gen_syn_burst.py [dst_ip] [port] [count]
"""
import sys, time

from scapy.all import IP, TCP, send

DST = sys.argv[1] if len(sys.argv) > 1 else '192.0.2.10'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
N = int(sys.argv[3]) if len(sys.argv) > 3 else 30

print(f'[*] {N} SYNs to {DST}:{PORT} (one port, no handshake -> flood shape, not a scan)')
sent = 0
for i in range(N):
    pkt = IP(src='198.51.100.9', dst=DST) / TCP(sport=40000 + (i % 20000),
                                                 dport=PORT, flags='S')
    try:
        send(pkt, verbose=0)
        sent += 1
    except OSError as e:
        print(f'    send failed: {e}')
        break
    time.sleep(0.02)
print(f'[+] sent {sent} SYN packets to {DST}:{PORT}')
time.sleep(20)   # let the 10s idle flow-finalisation flush emit conn events
