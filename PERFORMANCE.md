# Performance

No performance figure is committed or claimed. Sentinel produces machine-readable artifacts only when commands are run:

- `python3 -m eval.replay_eval <scenario>` → event rate and p50/p95/p99 latency from event ingestion to alert serialization.
- `make loadtest` → controlled synthetic-event envelope; this is explicitly **not** PCAP Mbps proof.
- `scripts/run_pcap_replay.sh <pcap> <mbps>` with live Zeek → the required production-like replay path.

For each final benchmark, save the exact command, PCAP SHA-256, rate, duration, host CPU/RAM, Docker/Zeek/Python version, queue lag, drops, CPU/memory and resulting artifacts. Do not infer a throughput target from a paced scenario rate.

`make capture-proof` creates an `artifacts/zeek-live-<UTC timestamp>/` directory with the actual Zeek/tcpreplay environment, RX/TX interface counters, routes, firewall policy, blocked-egress result, Zeek logs and worker summary. These artifacts are evidence of functional live capture and bounded pipeline processing; they are not advertised as a sustained external-network throughput benchmark.
