# Load Test — Local Processing Envelope

closed-loop synthetic-telemetry ingestion to in-memory alert creation; highest stable rate = last step sustaining >=95% of offered flows/sec with <1% drops

Command: `python3 -m eval.loadtest --duration 0.5 --rates 2000,5000`

Environment: Linux-6.12.107+deb13-amd64-x86_64-with-glibc2.41 · Python 3.13.5 · 16 CPUs

| Target f/s | Achieved | Mbps | Drops | p50 ms | p95 ms | p99 ms | CPU% | RSS MB | Stable |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| 2000 | 2000 | 3.405 | 0 (0.0%) | 0.051 | 0.098 | 0.115 | 94.2 | 165.1 | ✓ |
| 5000 | 5000 | 8.512 | 0 (0.0%) | 0.09 | 0.175 | 0.204 | 48.6 | 165.4 | ✓ |

Highest stable rate: **5000 flows/sec**.

Not a PCAP Mbps network benchmark. Redis-consumer stream lag/drops under the deployed path are exposed by the worker at /api/dashboard/summary.pipeline; run scripts/run_pcap_replay.sh with live Zeek for production-like proof.
