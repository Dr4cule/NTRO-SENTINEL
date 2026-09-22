<div align="center">

<img src="docs/assets/sentinel-logo.png" alt="NTRO Sentinel" width="120" height="120">

# NTRO Sentinel

**Passive, payload-blind threat detection for one-way IP traffic.**
Turns a mirrored copy of network *metadata* into explainable alerts, a live analyst dashboard, and tamper-evident forensic records — with no return path, no active probe, no blocking, and no TLS/QUIC decryption.

![Python](https://img.shields.io/badge/Python-3.11%2B-000?style=flat-square)
![Pipeline](https://img.shields.io/badge/pipeline-payload--blind-000?style=flat-square)
![Traffic](https://img.shields.io/badge/traffic-one--way-000?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-zero--egress-000?style=flat-square)
![Evidence](https://img.shields.io/badge/evidence-tamper--evident-000?style=flat-square)
![SIH](https://img.shields.io/badge/SIH_2026-PS_26145-c81e1e?style=flat-square)

</div>

---

Sentinel watches a *copy* of traffic and never touches payload bytes. It reads only metadata — IPs, ports, byte counts, timings, DNS query names, TLS fingerprints — runs six deterministic detectors over bounded time windows, correlates alerts per source, hash-chains them into an append-only store, and streams them to a single-file dashboard. It is built to run air-gapped and to survive massive traffic without unbounded memory or an un-scrollable UI.

Three constraints shape every design choice:

- **Payload-blind** — metadata only, never packet contents.
- **One-way** — the sensor can only *receive* a mirror; it never emits onto the monitored link.
- **Honest** — no fabricated metrics. Every number is produced by a committed script or not claimed at all.

## Project status

Everything below is built, wired end-to-end, and runnable today:

| Area | State |
|---|---|
| 6 detectors (ddos · c2 · dga/dns-tunnel · encrypted-malware · recon · exfiltration) | ✅ deterministic, explainable, MITRE-mapped |
| Streaming engine · per-source correlation · 30s dedup · bounded windows | ✅ |
| Hash-chained SQLite store + integrity verification | ✅ |
| FastAPI REST + WebSocket · single-file neo-brutalist dashboard | ✅ |
| Offline PCAP→events adapter + **24/7 live-capture / file-ingest service** | ✅ |
| Controlled-scenario evaluation (8/8 attack scenarios detected · benign FPR 0.0) | ✅ committed |
| Hybrid ML enrichment — DGA char-ngram classifier + exfil anomaly (IsolationForest), both optional & graceful | ✅ |
| Docker hardening · one-way proof scripts | ✅ |

Honest gaps (not yet done, by design — measure it or don't claim it):

- Scored **precision/recall/F1 on external labeled PCAPs** needs the Zeek Tier-A replay + dataset label-join.
- No external-network **Mbps throughput** benchmark is claimed (the load test is an in-process envelope).
- `encrypted_malware` is not exercised on the offline path (no JA3/TLS derived without Zeek).

## Architecture

```
             mirror / TAP (one-way)
                     │
   ┌─────────────────▼─────────────────┐
   │  ingest                            │   Zeek metadata  ── OR ──  scapy PCAP/live adapter
   │  (conn · dns · tls events)         │   (payload-blind, headers + DNS names only)
   └─────────────────┬─────────────────┘
                     │  events
   ┌─────────────────▼─────────────────┐
   │  Pipeline  (engine/stream_consumer)│   bounded feature windows → 6 detectors
   │  route → detect → dedup(30s)       │   → per-source correlation
   └─────────────────┬─────────────────┘
                     │  alerts (single writer)
   ┌─────────────────▼─────────────────┐
   │  hash-chained SQLite  (alertstore) │   record_hash = sha256(prev_hash + record)
   └─────────────────┬─────────────────┘
                     │
   ┌─────────────────▼─────────────────┐
   │  FastAPI REST + WebSocket → dashboard  (live, air-gapped, single file)
   └────────────────────────────────────┘
```

Every stage is **bounded**: feature windows evict by time *and* key count (max 4096), dedup caps alert volume to ≤1 per behavior per 30s, and every dashboard view caps its input and sorts by importance — so a spoofed million-source flood can neither OOM the worker nor make the UI un-scrollable.

### The six threat classes

| Class | Fires when (metadata only) | MITRE |
|---|---|---|
| `ddos` | `syn_count ≥ 20` or (`udp_count ≥ 20` and `unique_sources ≥ 8`); confidence scales with intensity | T1498 |
| `c2_beaconing` | ≥4 sessions, inter-arrival CV ≤ 0.15, persistence ≥ 60s, ≤2 dst ports | T1071.001 |
| `dga_dns_tunnel` | label length ≥ 18 **and** entropy ≥ 3.3, **or** ML DGA score ≥ 0.8 | T1071.004 / T1568.002 |
| `encrypted_malware` | TLS present **and** (out/in byte ratio > 8 **or** suspicious fingerprint) | T1071.001 |
| `recon_scan` | ≥12 unique dst ports (vertical) or ≥12 unique dst hosts (horizontal) | T1046 |
| `exfiltration` | outbound ≥ 500 KB **and** out/in ratio ≥ 5 | T1041 |

Each alert carries exact feature values, a normalized `confidence` (a detector score, **not** a calibrated probability), severity, MITRE tags, and the `model_version` that produced it — so it is auditable field by field. When one source trips ≥2 distinct classes, the correlator raises a single `correlated_multi_signal` incident instead of scattered blips.

## Quickstart

> **Dependencies.** Viewing the dashboard needs nothing but Python 3.11+ (stdlib only). Ingesting a PCAP or live traffic needs `scapy` (`pip install scapy`). The full FastAPI + WebSocket API and Docker stack need `pip install -r requirements.txt`.
>
> **ML enrichment (optional).** The DGA and exfiltration detectors take an optional ML second opinion; if the model isn't present (or was trained under a different scikit-learn) they degrade silently to their deterministic rules. It activates automatically in Docker (the image retrains at build). To activate locally: `MODEL_DIR=artifacts/models python3 -m models.train_models`, then run ingest with the same `MODEL_DIR`.

### 1 · See the dashboard — zero dependencies, ~30s

```bash
python3 scripts/preview_server.py 8001
# open http://localhost:8001  (reads the live artifacts/sentinel.db; edits preview on refresh)
```

### 2 · Analyze a capture file (PCAP, or Zeek/JSONL logs)

Feed a file straight into the store the dashboard reads, then exit:

```bash
python3 -m ingest.service --file /path/to/capture.pcap --once
```

Huge capture? Cap how many packets are parsed:

```bash
MAX_PACKETS=300000 python3 -m ingest.service --file big.pcap --once
```

Accepts `.pcap` / `.pcapng` / `.cap` and line-delimited `.jsonl` / Zeek-JSON. Refresh the dashboard and the new alerts appear. (To only print detections without writing the store: `python3 -m ingest.pcap_to_events <pcap> [max_packets]`.)

### 3 · Capture live traffic — run it 24/7

One long-running service captures a NIC *and* ingests drop-in files at the same time, feeding the same store live:

```bash
sudo python3 -m ingest.service --live eth0 --watch artifacts/inbox
```

- `--live eth0` — sniff the interface continuously (needs **root / CAP_NET_RAW**); flows finalize into events after ~10s idle, like Zeek closing a connection.
- `--watch artifacts/inbox` — drop a `.pcap`/`.jsonl` into the folder anytime; it's ingested and moved to `processed/`.

A single consumer thread is the **only** writer to the store, so the hash chain stays serialized no matter how many sources feed it. Leave it running; the dashboard updates live.

### 4 · Full stack (Docker — production-shaped)

```bash
docker compose up -d --build            # redis + streaming worker + hardened API
# open http://localhost:8000
curl localhost:8000/health              # status + chain validity + pipeline metrics
curl localhost:8000/api/evidence/verify # recompute & verify the whole hash chain
```

Containers run `read_only`, `cap_drop: ALL`, `no-new-privileges`, with pinned images and memory/CPU limits. Rebuild only the API after editing the dashboard: `docker compose up -d --build api`.

## Evidence & honesty discipline

This is the project's strongest rule, and it's enforced in code:

- **No fabricated numbers.** `PERFORMANCE.md` deliberately commits no figure. The evaluator reports scenario coverage, a confusion matrix, benign false-positive rate, and alert-level precision — and **explicitly refuses** to print flow-level F1, because homogeneous scenarios would make it a lie.
- **Tamper-evident.** Every alert is chained: `record_hash = sha256(prev_hash + canonical_json(record))`. Editing, reordering, or deleting past records breaks verification, surfaced at `/api/evidence/verify` and `/health`.
- **Traceable.** Every alert names the exact rule/model version that produced it and the feature values behind it.

```bash
make test         # unit suite (window eviction, all six detectors, dedup, FPR guard)
make evaluate     # controlled coverage + confusion + FPR → eval/results.{json,md}
make loadtest     # in-process throughput envelope → artifacts/loadtest.{json,md}
make check        # compileall + docker compose config  (CI-style gate)
```

## Repo map

```
ingest/       Zeek script + log tailer · pcap_to_events.py (offline adapter) · service.py (24/7 live+file)
features/     bounded feature windows (base.py = WindowState) + per-class extractors
detectors/    rules.py — the six deterministic detectors
correlation/  engine.py — per-source multi-signal correlation
engine/       stream_consumer.py (Pipeline + redis worker + jsonl runner), contracts, validation, metrics
alertstore/   store.py — hash-chained SQLite
api/          main.py — FastAPI REST + WebSocket, serves the dashboard
dashboard/    index.html — the single-file, zero-dependency UI
models/       train / evaluate / inference for the prototype ML models
eval/         run_suite.py · loadtest.py · cic_ids2017_coverage.py  (all non-inflationary)
scripts/      replay · live-capture · one-way-proof · demo · preview_server.py
docs/         DATASETS · LIMITATIONS · OPERATIONS · ENCLAVE_HARDENING · mitre_mapping · …
experiments/  datasets.yml (registry) · scenarios.yml (labels)
```

New to the codebase? [`interesting stuff.md`](interesting%20stuff.md) is the full context & decision log — what every stage does and *why*. Honest limits live in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md); the live-host procedure in [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

<div align="center"><sub>Built for SIH 2026 · Problem Statement 26145 (NTRO) — AI-based detection of cyber threats in unidirectional IP traffic. · <b>Measure it or don't claim it. Stay payload-blind and one-way.</b></sub></div>

