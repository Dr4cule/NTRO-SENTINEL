# Architecture

```text
permitted PCAP / passive mirror
         │ (traffic only)
         ▼
capture namespace: monitor NIC · no L3/default route · IPv6 off · OUTPUT DROP
         │ Zeek conn/dns/TLS + early connection metadata (no payload copied)
         ▼
incremental tailer ──► Redis Streams ──► bounded feature windows ──► six detectors
                                                                      │
             FastAPI/WebSocket ◄── SQLite evidence vault ◄── correlation/scoring
                    │                          │
              SOC dashboard               SHA-256 hash chain
```

The capture boundary is separate from the analytics Docker network. `scripts/setup_lab.sh` creates a source replay namespace and capture namespace joined by a veth; the capture monitor interface intentionally has no address. `verify_one_way.sh` records interface addresses, routes, IPv6 state, firewall policy, sockets, and a controlled failed egress test.

State is explicitly bounded and timestamp-evicted: DDoS 5s; recon/TLS 30s; DNS 60s; C2/exfil 300s. Late telemetry is evaluated against its provided timestamp and may be evicted immediately if outside the active window.
