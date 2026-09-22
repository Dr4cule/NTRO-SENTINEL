# Operations runbook

## Dashboard / controlled demo

Run `./scripts/run_demo.sh`, wait for the URL, and open `http://localhost:8000`. The services are Redis, detector worker and FastAPI dashboard. Stop them with `docker compose down`.

The script runs an API health preflight, gives the analyst a warm-up interval, performs a paced visible scenario story, and writes a timestamped evidence bundle. Set `DEMO_PACE=.30` to slow it further for a presentation or `DEMO_WARMUP_SECONDS=10` for more time to open the dashboard.

## Recommended judge run

Run `make judge-demo` and open `http://localhost:8000` during the warm-up. It first performs a full live proof within a disposable privileged Docker lab: checksummed safe PCAP → `tcpreplay` → live `zeek -i` on a one-way capture veth → incremental tailer → Redis Streams → detector worker → dashboard. It then adds the C2, encrypted-session and exfiltration controlled streaming scenarios so the dashboard displays all six PS classes. This is the strongest complete demo available without using any real production traffic.

## Live Zeek path

1. Install a pinned Zeek release and a compatible JA3/JA4 package on a Linux capture host; record versions in the final performance evidence.
2. `sudo ./scripts/setup_lab.sh` creates `ntro-capture` and `ntro-replay`. The capture interface is `ntro-mon0` and intentionally has no IP address.
3. Start `scripts/run_zeek.sh ntro-mon0`; it executes Zeek inside the capture namespace. Tail `conn.log`, `dns.log`, `ssl.log` and `early.log` independently with `ingest/tailer.py --redis-url ...`.
4. Replay an allowed PCAP through `scripts/run_pcap_replay.sh <pcap> <mbps>`.
5. Run `sudo ./scripts/verify_one_way.sh`; retain its exact output alongside benchmark artifacts.

`run_pcap_replay.sh` verifies `<pcap>.sha256` if provided. Never commit private or restricted PCAPs.

## Evidence response

Use `GET /api/evidence/verify` before and after a demonstration. The returned head hash identifies the current append-only evidence-chain head. This is a prototype tamper-evident chain—not an external blockchain, immutable storage, or a replacement for signed forensic storage.
