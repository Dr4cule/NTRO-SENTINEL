# Demo script

1. Run `make judge-demo`, then open `http://localhost:8000` during its warm-up.
2. State that phase one is a live Zeek 9.0 interface capture of a checksummed safe lab PCAP in a disposable one-way Docker namespace—not an offline `zeek -r` run.
3. Show the DDoS SYN, UDP-reflection, DNS-tunnel and vertical-scan alerts; click each alert for actual feature evidence and Zeek-derived five-tuples.
4. State that phase two adds controlled streaming C2, encrypted-metadata and exfiltration scenarios so all six classes are visible in the same dashboard.
5. Open `/api/evidence/verify`; show the verified hash chain. Open the latest `artifacts/zeek-live-*` folder and show no IP/default route, OUTPUT DROP, RX-only monitor counters, and blocked egress.
6. Explain pipeline health latency precisely: event ingestion to persisted alert. Do not advertise this as a public-PCAP Mbps benchmark.

The demo leaves `artifacts/zeek-live-<UTC timestamp>/` (live capture proof) and `artifacts/evidence-bundle-<UTC timestamp>/` (API/evidence hand-off) directories with SHA-256 manifests. Retain both after a judging run.
