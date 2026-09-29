# NTRO Sentinel — Full Project Context

Single-file engineering reference for the whole repository. Everything below was read from
the code and re-verified on 2026-09-29. Where this file and the code disagree, **the code
wins** — treat it as a map, not a substitute for reading the file it describes.

- **Project:** NTRO Sentinel
- **Built for:** SIH 2026, Problem Statement 26145 (NTRO) — AI-based detection of cyber threats in unidirectional IP traffic
- **Repository:** `github.com/Dr4cule/NTRO-SENTINEL` (branch `main`)
- **Stack:** Python 3.11+, stdlib-first. `scapy` for capture, `fastapi`/`uvicorn`/`redis`/`scikit-learn`/`joblib` for the full stack
- **Motto that governs the codebase:** *measure it or don't claim it*

---

## 1. What the system is

A **passive, payload-blind network threat detector**. It watches a *mirrored copy* of network
traffic and converts only metadata into explainable alerts, a live analyst dashboard, and
tamper-evident forensic records.

### The three non-negotiable constraints

| Constraint | Meaning | How it is enforced |
|---|---|---|
| **Payload-blind** | Never reads packet contents, never decrypts TLS/QUIC. Only L3/L4 headers, DNS question names, TLS handshake metadata. | No code path reads payload. Pcap adapter parses headers + DNS qname only (`ingest/pcap_to_events.py`). |
| **One-way** | The sensor can only *receive*. It never emits onto the monitored link, never probes, never blocks, no return path. | Capture namespace has no L3 address, no default route, IPv6 off, `OUTPUT DROP` (`scripts/setup_lab.sh`, `scripts/verify_one_way.sh`). |
| **Honest** | No fabricated numbers. Every metric comes from a committed script or is not claimed. | `PERFORMANCE.md` commits no figure. `eval/run_suite.py` explicitly *refuses* to print flow-level F1. Aggregate CSVs with no endpoints produce an *assessment*, not fabricated flow alerts. |

### Threat classes required by the problem statement

All six are implemented as deterministic rules, plus one correlation-derived meta-alert:

`ddos` · `c2_beaconing` · `dga_dns_tunnel` · `encrypted_malware` · `recon_scan` · `exfiltration`
(+ `correlated_multi_signal`, emitted as `c2_beaconing/correlated_multi_signal` to stay inside the 6-class enum)

---

## 2. Repository map

```
SIH26/
├── README.md                     # main entry doc, badges, quickstart
├── ARCHITECTURE.md               # the one diagram
├── PERFORMANCE.md                # deliberately empty of claims
├── context.md                    # THIS file
├── requirements.txt              # fastapi, uvicorn, redis, scikit-learn, joblib
├── Makefile                      # generate/demo/test/evaluate/train/loadtest/evidence/...
├── Dockerfile                    # python:3.11-slim, trains models at build, runs as user `sentinel`
├── docker-compose.yml            # redis + api + worker (+ trainer/evaluator profiles)
│
├── ingest/                       # TRAFFIC IN
│   ├── zeek/sentinel.zeek        # passive Zeek policy: JSON logs + early-connection stream
│   ├── tailer.py                 # Zeek JSON log -> normalized events -> Redis/stdout
│   ├── pcap_to_events.py         # offline+live scapy adapter: pcap/NIC -> Zeek-shaped events
│   ├── csv_to_events.py          # CSV ingest: endpoint-CSV -> conn events; aggregate -> assessment
│   └── service.py                # 24/7 service: --live / --watch / --file, single-writer design
│
├── features/                     # BOUNDED STATEFUL WINDOWS
│   ├── base.py                   # WindowState: time eviction + max_keys eviction
│   ├── ddos.py  c2_beacon.py  dga_dns.py  recon_scan.py  exfiltration.py  tls_metadata.py
│
├── detectors/
│   ├── rules.py                  # THE detector logic (all six)
│   └── c2.py ddos.py dga.py dns_tunnel.py exfil.py recon.py encrypted.py   # 1-line re-exports
│
├── correlation/engine.py         # per-source multi-signal correlation
│
├── engine/
│   ├── stream_consumer.py        # Pipeline + redis_worker + run_jsonl
│   ├── contracts.py              # THREATS, alert() constructor, severity mapping
│   ├── validation.py             # dependency-free alert contract guard
│   └── metrics.py                # StreamMetrics: 10k-latency ring, p50/p95/p99
│
├── alertstore/store.py           # hash-chained SQLite (append-only forensic vault)
│
├── api/main.py                   # FastAPI REST + WebSocket + serves dashboard
├── dashboard/index.html          # single-file, zero-dependency neo-brutalist SOC console
│
├── models/                       # OPTIONAL ML ENRICHMENT (never an alert gate)
│   ├── train_models.py  evaluate_models.py  inference.py
│   ├── artifacts/                # joblib + manifest + holdout eval (git-tracked)
│   └── model_cards/README.md
│
├── eval/                         # HONEST MEASUREMENT
│   ├── run_suite.py              # controlled scenario coverage, confusion, FPR
│   ├── replay_eval.py            # paced event->alert latency p50/p95/p99
│   ├── loadtest.py               # in-process throughput envelope
│   ├── cic_ids2017_coverage.py   # dataset fit/coverage matrix from REAL files
│   └── results.{json,md}
│
├── traffic-gen/
│   ├── generators/generate_scenarios.py   # 9 metadata JSONL scenarios (121 events)
│   ├── generators/generate_pcaps.py        # 5 safe TEST-NET pcaps + sha256
│   ├── scenarios/*.jsonl
│   └── pcaps/*.pcap(.sha256)
│
├── schemas/                      # alert.schema.json, telemetry.schema.json
├── scripts/                      # 15 operational scripts (replay, proof, demo, evidence, lab)
├── tap/Dockerfile                # Zeek 9.0 capture-boundary image
├── tests/                        # test_features.py (11) + test_csv_ingest.py (2)
├── experiments/                  # datasets.yml (provenance registry) + scenarios.yml (labels)
├── docs/                         # DATASETS, LIMITATIONS, OPERATIONS, ENCLAVE_HARDENING,
│                                 # FEATURES_AND_MODELS, mitre_mapping, DEMO_SCRIPT,
│                                 # DEPLOYMENT_COST, JUDGE_QA_PREP, SUBMISSION_CHECKLIST
├── artifacts/                    # RUNTIME OUTPUT (git-ignored): sentinel.db, bundles, proofs
└── .claude/ .kilo/              # agent/tooling config, not project code
```

---

## 3. Runtime data flow

```
permitted PCAP / passive mirror / live NIC
        │
        ▼
┌─ CAPTURE BOUNDARY ────────────────────────────────────────────┐
│ tier A: tcpreplay -> veth -> Zeek 9.0 (sentinel.zeek)          │
│ tier B: scapy adapter (pcap_to_events / LiveCapture)           │
│ tier C: CSV (endpoint-bearing -> events; aggregate -> assess)  │
│ In all cases: ONE-WAY, no payload, no return path              │
└──────────────────────────┬────────────────────────────────────┘
                           │  normalized events
                           ▼
        Redis Streams "telemetry"  (XADD, MAXLEN ~100k)
        consumer group "sentinel"  (XREADGROUP -> XACK)
                           │
                           ▼
┌─ PIPELINE (engine/stream_consumer.py) ────────────────────────┐
│  route by event kind -> update bounded feature windows          │
│  -> run 6 detectors -> dedup -> per-source correlation         │
└──────────────────────────┬────────────────────────────────────┘
                           │  validated alerts (single writer)
                           ▼
        Hash-chained SQLite (alertstore)  artifacts/sentinel.db
                           │
                           ▼
        FastAPI REST + WebSocket  ->  dashboard/index.html
        /api/evidence/verify recomputes the whole chain
```

### Event contract (what every ingest path must produce)

`schemas/telemetry.schema.json` requires `kind ∈ {conn, dns, tls, early_event}` plus `src_ip`,
`dst_ip`, `proto`. Canonical event fields:

```
conn / early_event : ts, src_ip, src_port, dst_ip, dst_port, proto,
                     orig_bytes, resp_bytes, conn_state (SF|S0|REJ|OTH|RSTO), duration, tcp_flags
dns                : ts, src_ip, dst_ip, proto, query, qtype, qtype_name, rcode, answers_count
tls                : ts, src_ip, dst_ip, proto, tls=True, tls_version, sni, ja3, ja4,
                     cipher, resumed, established
```

- `early_event` = an alert raised **without waiting** for a completed flow. This is what makes
  scan/SYN-flood detection possible before the flow closes.
- `ts` is the event timestamp (epoch float). Late events are evaluated against their own `ts`
  and may be evicted immediately if outside the active window — by design.
- `orig_bytes` / `resp_bytes` are *initiator → responder* direction bytes, normalized in the
  pcap adapter by direction (`_key` in `ingest/pcap_to_events.py`).

---

## 4. Feature windows (`features/`)

All windows are bounded by **time eviction** and **key-count eviction** (`max_keys=4096`),
implemented once in `features/base.py:WindowState`. A spoofed million-source flood cannot OOM
the worker.

| Module | Window | Key | Emitted features |
|---|---:|---|---|
| `ddos.py DDoSFeatures` | 5 s | `dst_ip` | `packet_rate, syn_count, udp_count, unique_sources, source_ip_entropy, completion_ratio, dst_concentration, inbound_bytes, outbound_bytes` |
| `c2_beacon.py C2Features` | 300 s | `src_ip\|dst_ip` | `session_count, iat_mean, iat_cv, period_seconds, persistence_seconds, destination_port_count, destination` |
| `dga_dns.py DNSFeatures` | 60 s | `src_ip\|parent_domain` | `query, label_length, label_entropy, query_rate, unique_subdomains` |
| `recon_scan.py ReconFeatures` | 30 s | `src_ip` | `unique_dst_hosts, unique_dst_ports, scan_rate, failure_ratio` |
| `exfiltration.py ExfilFeatures` | 300 s | `src_ip\|dst_ip` | `outbound_bytes, inbound_bytes, outbound_inbound_ratio, session_count, destination` |
| `tls_metadata.py TLSFeatures` | 30 s | `src_ip` | `ja3, ja4, tls_version, sni, outbound_inbound_ratio, duration, host_sessions` |

Entropy helpers: `features/dga_dns.py:entropy` (Shannon over label chars),
`features/ddos.py` (Shannon over source-IP distribution). IAT CV = `pstdev(iats) / mean(iats)`.

---

## 5. Detectors (`detectors/rules.py`)

Every detector returns a validated alert dict or `None`. All logic lives in `rules.py`; the
per-class modules (`detectors/c2.py` etc.) are one-line re-exports for import convenience.

### Pre-filters shared across rules

| Helper | Purpose |
|---|---|
| `_is_local_dest(ip)` | RFC1918, CGNAT `100.64/10`, loopback, link-local, `224.0.0.0/4` → not internet C2. Deliberately **excludes** TEST-NET (`192.0.2/198.51.100/203.0.113`) because those stand in for real public IPs in fixtures. |
| `_known_good_domain(q)` | 20 CDN/cloud registrable parents (cloudfront, amazonaws, google, akamai, azure…). Long high-entropy sublabels under these are cache keys, not DGA. |
| `_is_test_net(ip)` | Recognizes the three documentation ranges. |
| `_is_noise_traffic(e)` | **Added 2026-09-29** (see §11). Unicast-only + noise-port skip. |
| `_NOISE_PORTS` | `{5353,1900,5355,67,68,123,3478,5678,5228}` — mDNS, SSDP, LLMNR, DHCP, NTP, STUN, Google push. Suppresses **C2 only**. |

### Current rules and thresholds

| Class | Condition (current) | Subtype | Conf | MITRE | `model_version` |
|---|---|---|---|---|---|
| `ddos` | skip noise traffic; then `syn_count>=20 AND completion_ratio<=.5` **OR** (`udp_count>=20 AND unique_sources>=8`) | `udp_reflection_amplification` if udp branch, else `spoof_like_source_flood` if `source_ip_entropy>=3.5`, else `syn_flood` | `min(1,(syn+udp)/40)` | T1498 | `ddos-rules-v2` |
| `c2_beaconing` | skip local dest; skip noise traffic; `session_count>=5 AND iat_cv<=.12 AND persistence>=120 AND destination_port_count<=2`; **then** direction gate (dst_port not ephemeral) **and** size gate (`mean_outbound_bytes<=1500`, `mean_inbound_bytes<=1500`) **and** reputation rank | `periodic_session` if provider/reputation downgraded, else `periodic_beacon` | `0.45` downgraded, `0.8` real | T1071.001 | `c2-structure-v1` |
| `dga_dns_tunnel` | skip known-good parent; `(label_length>=18 AND label_entropy>=3.3)` **OR** (`dga_score(first_label)>=.8`) | `dns_tunnel` if `query_rate>=.05 AND unique_subdomains>=3`, else `dga_domain` | `max(min(.95,entropy/5), learned or 0)` | T1071.004 / T1568.002 | `dns-lexical-ml-v1` / `dns-lexical-v1` |
| `encrypted_malware` | `e.tls AND e.suspicious_fingerprint` (Zeek path, strong). Fallback when no JA3: `tls AND ratio>=8 AND host_sessions<=2 AND destination unattributed` | `metadata_anomaly` / `upload_channel_anomaly` | `0.7` / `0.5` | T1071.001 | `tls-metadata-v1` / `tls-metadata-heuristic-v1` |
| `recon_scan` | `(unique_dst_ports>=12 OR unique_dst_hosts>=12) AND failure_ratio>=.5` | `vertical_scan` if ports>=hosts else `horizontal_scan` | `0.8` | T1046 | `recon-fanout-v1` |
| `exfiltration` | `outbound_bytes>=500000 AND outbound_inbound_ratio>=5 AND session_count>=3`; ASN reputation Ranks (provider dest → `0.5/medium`), ML only raises 0.8→0.9 | `sustained_outbound_anomaly` | `0.5` provider, else `0.9` if ML flags / `0.8` | T1041 | `exfil-rules-v2` / `exfil-baseline-ml-v1` |

### Reasoning behind the non-obvious gates

- **`completion_ratio` on DDoS** — a CI runner or load test that sends 20+ SYNs but *completes*
  them is not a flood. Real SYN floods are half-open (S0/REJ, low completion). Requires a tap
  that sees both directions.
- **`failure_ratio` on recon** — a browser loading a page from 30 CDN hosts is a fan-out with
  *low* failure. Scans hit closed ports → S0/REJ → high failure.
- **`session_count>=3` on exfil** — one 600 KB HTTPS upload is a photo/attachment. Staged exfil
  is *sustained*.
- **`suspicious_fingerprint` preferred, but no longer required (F-10 fix)** — out/in ratio > 8
  alone would fire on every photo upload, backup and webmail attachment, so ratio is never a
  gate by itself. Because the scapy/live path derives no JA3, the old condition could never be
  true there and the detector was dead outside Zeek. The fallback requires **three** independent
  anomalies to agree — upload asymmetry `ratio>=8`, low host diversity `host_sessions<=2`, and a
  destination the ASN table cannot attribute — and scores `0.5` vs `0.7` for a real fingerprint
  match, so it ranks below the strong path rather than pretending to equal it.
- **Exfil reputation ranking** — 21 consecutive live alerts were all to one Cloudflare IP
  (500 KB–1 MB, ratio 8–53, 7–29 sessions): cloud sync/backup, byte-for-byte the shape of staged
  exfil. Volume cannot separate them, so the destination network Ranks the alert to `0.5/medium`.
  It is **never** suppressed — a real exfil to a CDN host must stay visible.

---

## 6. Deduplication (`engine/stream_consumer.py:Pipeline.process`)

Alert key = `(threat_class, subtype, aggregation_key)`, where `aggregation_key` comes from the
detector's `supporting_evidence` (falls back to `src_ip|dst_ip`).

| Threat | Dedup window | Reason |
|---|---:|---|
| `c2_beaconing` | **300 s** | A beacon persists for the full 300 s feature window; a 30 s dedup re-emitted the same beacon ~9×. Set to 300 s on 2026-09-29. |
| everything else | 30 s | Bursty classes (DDoS, recon) legitimately need re-emission. |

`Pipeline.process` routing:

```python
kind in (conn, early_event) -> ddos, c2, recon, exfil
kind == dns                 -> dns
e.get('tls')                -> encrypted
then: dedup -> correlator.process(fresh) -> return
```

---

## 7. Correlation (`correlation/engine.py`)

- Keeps the **last 8 alerts per `src_ip`** (the class-count context window).
- When **≥3 distinct `threat_class`** exist in that buffer, emits one synthesis alert.
- **Re-fire control:** a TTL of `SUPPRESS_SECONDS = 3600` per source. The 8-alert deque alone
  was not enough — a source that keeps producing 3+ classes flushed the
  `correlated_multi_signal` marker within 8 events and then re-fired on *every* subsequent
  event (reproduced: 4 fires in 6 events, 13+ in 40). The cooldown bounds it to one correlated
  alert per source per hour; `process()` also accepts an injectable `clock`/`now` for tests.
- Confidence is **capped at the strongest constituent** (`min(0.9, max(confidences))`) —
  correlation must never invent certainty its evidence doesn't support.
- Emitted as `c2_beaconing/correlated_multi_signal` because `engine/validation.py` enforces
  `threat_class ∈ THREATS` (the six canonical classes). Evidence carries `aggregation_key`,
  `window_seconds: 300`, `underlying_alert_ids`, and the sorted `classes`.
- The 3-class threshold (was 2) was raised on 2026-09-29 so two weak signals cannot forge a
  strong incident.

---

## 8. Alert contract (`engine/contracts.py`, `engine/validation.py`, `schemas/`)

`engine/contracts.py:alert()` builds and immediately validates every alert:

```json
{
  "alert_id": "<uuid4>",
  "timestamp": "<UTC ISO8601>",
  "flow_id": {"src_ip","src_port","dst_ip","dst_port","proto"},
  "threat_class": "ddos|c2_beaconing|dga_dns_tunnel|encrypted_malware|recon_scan|exfiltration",
  "subtype": "<specific behavior>",
  "confidence": 0.0-1.0,
  "severity": "low|medium|high|critical",
  "supporting_evidence": { ...exact feature values + aggregation_key + window... },
  "mitre_attack": ["T1498"],
  "model_version": "<rule-or-model id>"
}
```

- `confidence` is a **normalized detector score, not a calibrated probability**. Severity is a
  pure threshold map: `>=0.9 critical`, `>=0.7 high`, `>=0.45 medium`, else `low`.
- `validate_alert` is dependency-free and raises `ValueError` on: missing keys, wrong types,
  `flow_id` key set != the exact 5, unknown threat class, bad severity, non-numeric or
  out-of-range confidence, and **boolean** confidence (`bool` subclasses `int`, so
  `confidence=True` would otherwise pass the type gate and silently land in `low`).
  An invalid alert is never stored.
- MITRE mapping: DGA T1568.002 · DNS tunnel T1071.004 · web C2/beaconing T1071.001 ·
  network service scanning T1046 · exfil over C2 T1041 · DDoS T1498.

---

## 9. Forensic store (`alertstore/store.py`)

Append-only SQLite, default `artifacts/sentinel.db` (override `ALERT_DB`).

```sql
alerts(seq INTEGER PK AUTOINCREMENT, alert_id TEXT UNIQUE, timestamp TEXT, threat_class TEXT,
       severity TEXT, confidence REAL, src_ip TEXT, dst_ip TEXT,
       record_json TEXT,        -- canonical: json.dumps(sort_keys=True, separators=(',',':'))
       prev_hash TEXT, record_hash TEXT)
telemetry_metrics(metric_ts, events_total, alerts_total, stream_lag, p95_latency_ms, throughput_eps)
```

- **Hash chain:** `record_hash = sha256(prev_hash + canonical_json)`, `prev_hash` = previous
  row's `record_hash`, genesis `'0'*64`.
- **Idempotent:** a duplicate `alert_id` raises `IntegrityError`, caught → `append()` returns
  `False` instead of corrupting the chain.
- `WAL` journal + `busy_timeout=5000` so readers (API) don't block the single writer.
- `verify_chain()` walks every row and returns `{valid, checked, head_hash}` or
  `{valid: False, checked, failed_sequence}`. Exposed at `/api/evidence/verify` and `/health`.
- API: `list(threat_class, severity, limit≤1000)`, `summary()`, `metric(**d)`.

**Consequence to remember:** the store is *append-only*. Fixing a detector does not erase
already-stored alerts — they remain visible (and correctly chained) forever. Only deleting the
DB file produces a clean dashboard.

---

## 10. Delivery surface

### API (`api/main.py`)

Reads are open (analyst enclave); **writes require a bearer token** (`api/auth.py`).

| Method | Route | Auth | Behavior |
|---|---|---|---|
| GET | `/health` | open | `{status, version, store, chain, pipeline, write_auth, max_upload_mb}` |
| GET | `/api/alerts` | open | Query: `threat_class`, `severity`, `limit` (1–1000, default 250). Newest first. |
| POST | `/api/alerts` | **bearer** | 201. Body validated by `IncomingAlert` (pydantic). |
| POST | `/api/ingest` | **bearer** | Streamed to a temp file in chunks, aborted at `MAX_UPLOAD_BYTES` (default **100 MB**, `MAX_UPLOAD_MB`) → `ingest_upload_path`. 413 over cap, 400 empty. |
| GET | `/api/dashboard/summary` | `{total_alerts, by_class, by_severity, pipeline}` |
| GET | `/api/metrics` | `summary()['pipeline']` (events_total, alerts_total, stream_lag, p95_latency_ms, throughput_eps) |
| GET | `/api/evidence/verify` | Recompute + verify the full chain. |
| GET | `/api/incidents` | Group last 1000 alerts by `flow_id.src_ip`; `risk = min(100, Σ round(conf*18))`; server-side sort by risk desc. |
| WS | `/ws/alerts` | Read-only, no token. Polls `store.list(limit=100)` every 1 s; pushes only when `alerts[0].alert_id` changes. Rejects a cross-origin handshake (closes `1008`). |
| GET | `/` | `FileResponse(dashboard/index.html)`. |

### Write auth (`api/auth.py`)

- `SENTINEL_API_TOKEN` (env / `.env`) gates `POST /api/alerts` and `POST /api/ingest`.
- `Authorization: Bearer <token>`, compared with `hmac.compare_digest` (constant-time).
- **Fails closed:** with the variable unset the endpoints return `503`, they do not fall open.
  `docker-compose.yml` uses `${SENTINEL_API_TOKEN:?…}` so compose refuses to start without it.
- Reads (`/api/alerts`, `/api/dashboard/summary`, `/api/metrics`, `/api/evidence/verify`,
  `/health`, `/`, `/ws/alerts`) stay open — gating them would break the analyst demo.
- The dashboard prompts for the token once on a `401`/`503` and keeps it in `sessionStorage`
  for that tab only.

⚠️ Documented race: an upload *while the Redis worker is writing* can race the hash chain.
Safe when the worker is idle (default compose). `run_in_threadpool` keeps the event loop free.

### Dashboard (`dashboard/index.html`)

Single file, no build step, no CDN, no external assets (logo is inlined base64), neo-brutalist
CSS (hard black edges, offset shadows, blueprint grid). Views:

1. **Command centre** — 5 KPI cards (total / critical / eps / p95 / lag) + stacked
   alerts-over-time SVG (14 buckets) + per-class distribution bars
2. **Threat activity** — detection feed, 60 rows/page, search `q`, class + severity filters,
   click-through drawer with full `supporting_evidence` table, MITRE links, raw JSON
3. **Relationship graph** — bipartite src→dst, top 7×7 (≤49 edges), edge color = dominant
   class, width = volume, hover isolates
4. **Confidence histogram** — 10 bins with guides at 0.45 / 0.7 / 0.9
5. **Top hosts** — top 6 sources with class tags
6. **Incidents** — per-source risk cards with risk meters
7. **Evidence vault** — `Upload capture` button → `POST /api/ingest`; live chain-integrity chip

Data: `Promise.all` over 4 REST endpoints + `WebSocket(/ws/alerts)` + a 5 s `setInterval` poll
as fallback. `preview_server.py` does not implement `/ws/alerts`, so console 404s there are
expected and harmless.

`scripts/preview_server.py` mirrors the same four GET endpoints with **stdlib only** on `:8001`.
⚠️ It is a single-threaded `HTTPServer`: under concurrent browser fetches while a root writer
holds the SQLite lock, it can wedge. Symptom is the dashboard spinning on "Loading". Fix is to
restart it (`kill <pid>` then re-run) — the single-threaded model is the root cause, not the DB.

---

## 11. Ingest paths (`ingest/`) — all four, and when to use which

| Path | Command | Notes |
|---|---|---|
| **A · Zeek (production-shaped)** | `sudo ./scripts/run_pcap_replay.sh <pcap> [mbps]` → tcpreplay into the `ntro-capture` netns → Zeek 9.0 `sentinel.zeek` → `ingest/tailer.py` → Redis | The only path that yields JA3/JA4. `ingest/zeek/sentinel.zeek` sets `LogAscii::use_json=T`, defines a `Sentinel::Info` record, and logs on `new_connection` — it never opens a connection or reads decrypted payloads. |
| **B · Offline pcap adapter** | `python3 -m ingest.pcap_to_events <pcap> [max]` (prints only) or `python3 -m ingest.service --file x.pcap --once` (writes store) | scapy `PcapReader`. Derives `conn_state` (`S0/REJ` attempt, `SF` completed, `RSTO/OTH`), byte counts from L4 payload length, DNS qnames. **No JA3** → no `encrypted_malware`. `MAX_PACKETS` caps parsing (default 2,000,000). |
| **C · Live capture (24/7)** | `sudo python3 -m ingest.service --live <iface> [--watch artifacts/inbox]` | Needs **root or `CAP_NET_RAW`** — without it, `socket(AF_PACKET)` fails `PermissionError: Errno 1`. ⚠️ **The sniffer failure is silent**: `AsyncSniffer` runs in a thread, so `service.py` prints "capturing" and then ingests nothing. Verify by watching `events_total` actually grow. `LiveCapture` closes flows after `idle=10 s` of silence (mirrors Zeek), `max_flows=50000` bounds memory. Interface name is validated against `get_if_list()` and fails loud. |
| **D · CSV (added 2026-09-29)** | `ingest/csv_to_events.py` | Two flavors, decided by header inspection — see below. |

### CSV ingest in detail

`has_endpoints(fieldnames)` returns True when the header carries `src_ip` **and** `dst_ip`
(tolerant matching: BOM-stripped, whitespace-trimmed, case-insensitive, with alias lists —
`Source IP`, `src ip`, `id.orig_h`, `srcip`, …). Then:

- **Endpoint-bearing CSV** → `read_conn_events` yields `kind=conn` events identical in shape to
  the Zeek/tailer output. Also normalizes: `Protocol` numeric → `tcp/udp/icmp`;
  `SYN/ACK/FIN/RST Flag Count` → a `conn_state` (`S0`/`REJ`/`SF`/`OTH`); `Flow Duration` in
  microseconds → seconds; epoch or several datetime formats → `ts`. These then flow through the
  normal `Pipeline`, so **all detectors work on endpoint CSVs**.
- **Endpoint-less aggregate CSV** (CICFlowMeter-style: 78 flow statistics + `Label`, no IPs, no
  timestamp) → `analyze_aggregate` instead. Per-flow attribution is *impossible* without
  endpoints, so **no alerts are fabricated**. It returns a streaming assessment: row count,
  label census, `ddos_share`, SYN-heavy fraction, mean flow duration / packets-per-second /
  forward bytes, and top-10 destination ports with their DDoS share.

Verified on the real file `~/Downloads/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
(74 MB, 225,745 rows, 1.3 s): endpoint-less → assessment only. The assessment is
*meaningful*: `DDoS share 0.567` (128,027 DDoS / 97,718 BENIGN), and destination port **80
carries 93.5 % of its 136,951 flows as DDoS** while ports 53/443 are 0 % — a textbook HTTP
flood afternoon. That port concentration is the DDoS signal; per-victim attribution would need
the Friday **PCAP** through path A.

Accepted upload extensions: `.pcap .pcapng .cap .csv .jsonl .json .log`. Unknown suffixes are
coerced to `.jsonl` (line-JSON). `MAX_CSV_ROWS` caps row parsing (default 2,000,000).

### Single-writer discipline

`ingest/service.py:consumer` is the **only** thread that writes to the store, so the hash chain
stays serialized regardless of how many sources feed one queue. Uploads serialize behind
`_UPLOAD_LOCK`. In Docker, the Redis worker is the live writer.

---

## 12. ML models (`models/`) — enrichment only, currently inactive

| Artifact | Model | Role |
|---|---|---|
| `dga_char_ngrams.joblib` | char TF-IDF (2–5 gram) + LogisticRegression | Second opinion in `rules.dns`: `lexical OR learned>=.8` |
| `exfil_baseline.joblib` | IsolationForest (`contamination=.05`) | Second opinion in `rules.exfil`: **only** raises confidence 0.8 → 0.9, never gates |

`models/inference.py:_load` enforces **two** gates before a joblib file is unpickled:

1. **SHA-256 sidecar** — `training_manifest.json['sha256'][filename]` is compared against a
   streamed digest of the artifact. joblib files are pickles, so loading one executes it;
   anything able to write `MODEL_DIR` would otherwise be arbitrary code execution inside the
   detector. A mismatched, missing, or tampered artifact is refused **before** unpickling, and
   a manifest with no digest fails closed.
2. **scikit-learn version gate** — compares `training_manifest.json['scikit_learn_version']`
   against the runtime sklearn.

Any failure returns `None`, so the detectors silently fall back to their deterministic rules.
`models/train_models.py` writes the digests on every run.

> **Live status (2026-09-29): the models are INACTIVE.** Artifacts were trained under
> `scikit-learn 1.6.0`; the host runtime is `1.8.0`. The gate returns `None`, so *every* alert
> currently on the dashboard came from deterministic rules alone. Retrain with
> `MODEL_DIR=artifacts/models python3 -m models.train_models` to reactivate.

Training data is deliberately toy: 8 benign words × 40 vs 250 random 18-char strings
(`train_models.py:17`). Holdout (`evaluate_models.py`, seed 26146) reports P/R/F1 = 1.0 — that
is *reproducibility evidence for the train/load/eval path only*, not a real-world DGA claim.
Both `models/model_cards/README.md` and `docs/FEATURES_AND_MODELS.md` state this explicitly.
`models/inference.py` has a runnable self-check (`python3 -m models.inference`) that trains into
a temp dir and asserts the fallback behavior.

---

## 13. Evaluation & the honesty discipline

| Command | Output | What it measures |
|---|---|---|
| `make test` | 108 unit tests | `test_features.py` (13: window eviction, six detection paths, DDoS subtypes + contract shape, benign FPR = 0, dedup, loadtest) · `test_csv_ingest.py` (2: both CSV flavors) · `test_c2_structure.py` (24: structural C2 gates, direction/size/reputation, provider downgrade, fail-open semantics, mDNS-DDoS suppression, and the 443-must-not-downgrade regression guard) · `test_contracts_and_security.py` (~30 **negative** tests: bool/out-of-range/non-numeric confidence, missing/mistyped contract fields, exact `flow_id` keys, duplicate `alert_id` → `IntegrityError` → idempotent, **tampered / deleted / reordered** chain rows → `verify_chain` invalid, correlation suppression, CSV rejection, `Infinity` values, BOM/space headers, upload cap < container memory, auth contract) · `test_models_and_fallbacks.py` (16: train/eval vocabulary disjointness guards, exfil reputation never-silences invariant, encrypted fallback three-signal requirement) · `test_c2_structure.py::ReconFanout` (8: browser-vs-sweep discrimination, port-diversity and provider-spread downgrades, and the boundary guard that a 0.50-failure nmap sweep still fires) · `test_model_integrity.py` (7: manifest digests present and matching disk, stale-leaked-eval guard, missing-dir → None, absent-digest fails closed) · `test_api_auth.py` (9 API-level: 503 unconfigured, 401 missing/wrong token, 201 correct, reads open, 413 oversized, 400 empty; skipped if `fastapi`/`httpx` absent) |
| `make evaluate` | `eval/results.{json,md}` | Scenario-level coverage, truth×pred confusion, benign FPR, **alert-level** precision |
| `make loadtest` | `artifacts/loadtest.{json,md}` | In-process paced-replay envelope (~5000 flows/s on a dev box) — **explicitly NOT a PCAP Mbps proof** |
| `make model-eval` | `models/artifacts/dga_holdout_evaluation.json` | Disjoint generated holdout, P/R/F1 + confusion |
| `make evidence` | `artifacts/evidence-bundle-<UTC>/` | health + summary + verify + alerts + compose ps + SHA256SUMS |
| `eval/cic_ids2017_coverage.py` | `eval/cic_ids2017_coverage.{json,md}` | Dataset fit matrix computed from the **real** files, never copied from a paper |

**The hard rule:** `eval/run_suite.py` reports *scenario-level* detection and *alert-level*
precision, and its `confusion_and_precision` docstring states flow-level recall/F1 is
"intentionally not claimed" because homogeneous scenarios would make it a lie. One aggregated
alert can cover many flows, so flow-level F1 is not computable from this corpus.

**Current results (re-verified 2026-09-29):** `8/8` attack scenarios detected · benign alerts
`0` (FPR `0.0`) · DDoS subtype scenarios matched `3/3` · `108/108` tests pass, 0 skips.

**What is NOT claimed** (from `README.md` + `PERFORMANCE.md` + `docs/LIMITATIONS.md`):
- No scored precision/recall/F1 on external labeled PCAPs — that needs the Zeek Tier-A replay
  plus a dataset label join (IP + time + port).
- No external-network Mbps throughput benchmark.
- `encrypted_malware` is not exercised on the offline path (no JA3 without Zeek).
- The lab is a *software* namespace diode, not a certified hardware one.
- Scenarios are generated metadata, not a substitute for public-PCAP validation.
- SQLite, not PostgreSQL (explicitly supported reduced local demo store).
- TLS/QUIC payloads are never decrypted or stored.

---

## 14. Datasets registry (`experiments/datasets.yml`)

| Dataset | Coverage verdict | Correct path |
|---|---|---|
| `sentinel-safe-lab-pcaps` | 5 generated TEST-NET pcaps (`safe_syn_flood`, `safe_udp_reflection`, `safe_dns_tunnel`, `safe_recon`, `safe_mixed`) + sha256 | Replay into the isolated Docker lab |
| `sentinel-metadata-scenarios` | 9 JSONL scenarios covering all six classes (121 events) | JSONL replay into Redis |
| `cic-ids2017-flow-feature-parquet` | **NO for all six detectors.** 2.3 M flows of 78 statistical features + Label only; the IP/port/DNS/TLS/timestamp metadata every detector groups on is absent. | Use the CIC-IDS2017 **PCAPs** through Zeek (Tier A) |
| `cic-ids2017-thursday-pcap` | **PARTIAL/YES.** 800 k packets → 14,565 events → 118 alerts, plumbing intact, p50/p95/p99 = 0.068/0.61/0.87 ms. But the sample predates the labeled attack windows and all 118 alerts were false positives from normal RFC1918 browsing/DNS. | Replay the full PCAP through Zeek and join CIC ground truth |

That second row is the single most important calibration finding in the repo: **the lab-tuned
thresholds over-fire on raw enterprise traffic.** It is the same failure mode reproduced
independently during live capture on `wlp0s20f3` (see §15).

---

## 15. Live-capture findings on `wlp0s20f3` (2026-09-29, real production-shaped test)

A real NIC capture on a laptop on `172.168.1.142/22` (WiFi, `wlp0s20f3`, Chrome + VS Code +
Claude Code active) produced **~49 `c2_beaconing` alerts in minutes** with a benign FPR of
essentially 100 %. Root cause and fix:

| FP source | Why naive periodicity fired | Fix applied |
|---|---|---|
| mDNS `fe80::… → ff02::fb:5353` | 45 s periodic mDNS queries → `session_count` and CV satisfied | `_is_local_dest` missed IPv6 **and** the public-numbered LAN `172.168/22` (not in `172.16/12`). New `_is_noise_traffic` drops `is_multicast / is_link_local / is_loopback / is_reserved / 255.255.255.255 / *.255` |
| LAN broadcast `172.168.0.1 → 255.255.255.255:5678` and subnet broadcast `→ 172.168.3.255` | same | same |
| Google push `74.125.130.188:5228` | 45 s exact-period push | port `5228` in `_NOISE_PORTS` |
| STUN `3478`, SSDP `5678`, mDNS `5353`, DHCP/NTP | periodic | ports in `_NOISE_PORTS` |
| Chrome HTTPS keepalives to Cloudflare/Akamai `443` | 30–55 s exactly periodic to a *public* IP, 1 dst port | survived — see residual note |

Changes committed as `1670e67`:
1. `detectors/rules.py` — `_is_noise_traffic`, `_is_test_net`, `_NOISE_PORTS`; C2 gate tightened
   `4/60s/cv.15 → 5/120s/cv.12`; `model_version` bumped to `c2-periodicity-v2`.
2. `engine/stream_consumer.py` — `self.dedup_windows = {'c2_beaconing': 300}`; per-threat dedup.

Post-fix verification: mDNS / broadcast / subnet-broadcast / `5228` cases all → **0 alerts**;
the eval C2 fixture and an unknown-public `443` beacon still fire. Live rate dropped from ~9
alerts per beacon to 1 per 300 s per flow.

### 15.1 The C2 false-positive problem, and how it was actually solved (2026-09-29)

**The problem, stated honestly.** Low-jitter periodicity *cannot* distinguish malware phone-home
from a browser keepalive, an IMAP IDLE stream, or a push channel. All four produce "N sessions,
tiny CV, one port, sustained for minutes". The first two fixes (noise-port skip + 300 s dedup)
reduced the *volume* of false alerts but not their *existence*: over a full capture session the
C2 class accumulated 630 alerts, and reverse-DNS plus ASN lookup proved the destinations were
GitHub (`lb-140-82-114-26-iad.github.com`), Google, Cloudflare, Amazon, and
WhatsApp's CDN (`whatsapp-cdn-shv-01-hyd1.fbcdn.net`). A detector that fires on WhatsApp is not
a detector.

**Why not another threshold.** Any looser timing threshold makes it worse. The answer had to be
*additional independent evidence*, so three structural gates now sit in front of the C2 verdict:

| Gate | Rule | What it removes | Measured |
|---|---|---|---|
| **Direction** | A beacon is a *client request*. `dst_port > 1024` and not a long-idle protocol means the remote side is the client, i.e. this is a response returning. | 354 of 630 | the single largest win |
| **Size** | A heartbeat is small in *both* directions. `mean_outbound_bytes > 1500` or `mean_inbound_bytes > 1500` means the window is transferring content (a page load, a file), not polling. | folded into the rest | kills CDN/media sessions |
| **Reputation** | The destination's **autonomous system** is resolved offline and used to *rank*, never to suppress. | converts 251 alerts from `high` → `medium` | 100% match on real keepalive dests |

**Direction gate — port-range design, and the trap.** The naive version put `443` in the
"service ports" allowlist, which is a serious error: **443 is the primary malware C2 port**, so
that single choice would have downgraded essentially every real implant to `medium`. The list is
now `_LONG_IDLE_PORTS` — only protocols with a *permanent idle channel by design*
(SMTP/IMAP/POP 25/110/143/465/587/993/995/5222/5223/5944, STUN/push 3478/5228, VoIP 5060/51820,
IRC/XMPP 6667/6697/1633, DNS 53) — and it is used **only** for the ephemeral-range exemption.
An `https/443` beacon to an unattributable host therefore still lands at `high`, which is
correct. `tests/test_c2_structure.py` pins this as a regression guard.

**Reputation layer (`detectors/reputation.py`).** A static, air-gapped IP→ASN table
(`detectors/asn_prefixes.json`, ~17.6k BGP ranges, built by `scripts/build_asn_reputation.py`
from the iptoasn.com snapshot) is binary-searched at `O(log n)` with no network access at
runtime — the enclave must work air-gapped. The ASN set is **hand-curated** (33 providers:
Cloudflare, Fastly, Akamai, Google, AWS, Azure, GitHub, Meta, Anthropic, Oracle, …).

> Two rejected approaches are worth recording. A hand-typed IP-prefix list matched only **50%**
> of the real keepalive destinations. A name-regex over the same BGP dump was *worse*: it swept in
> IBM research networks, a shipping registry and an unrelated telecom — 314 ASNs, which would
> have "reputation-downgraded" nearly the entire internet. Curating by hand fixed the coverage
> problem and the precision problem at once.

**Fail-open is a safety property.** `reputation()` has no `'benign'` return value at all. An
unresolvable, malformed, IPv6, or unattributed address returns `'unknown'`, which is the *loud*
class. A missing or corrupt table must never make the detector quieter — it fails to
`unavailable`, which the caller treats as unknown. Provenance (`asn`, `asn_name`, `reputation`,
`downgrade_reason`) is written into `supporting_evidence` so an analyst can audit every call.

**Measured result** (replaying all 684 stored live alerts through the new rules):

| Class | Stored | Still fires | Suppressed | Remaining severity |
|---|---:|---:|---:|---|
| `c2_beaconing` | 630 | 252 | **378** | **1 × high**, and that single one is the eval C2 *fixture* (`198.51.100.88`). All 251 real ones are `periodic_session / medium`. |
| `ddos` | 41 | 3 | **38** | the 3 survivors are genuine TEST-NET reflection fixtures |

**Reading the feed now.** `periodic_beacon / high` means "beacon-shaped, to a network we cannot
attribute" — act on it. `periodic_session / medium` means "beacon-shaped to Cloudflare/Google/
GitHub" — expect keepalives, investigate only with a second signal. The distinction is
mechanical and auditable, not a judgement call.

### Residual known issues (NOT yet fixed)

1. ~~`c2_beaconing` over-fires on keepalives~~ — **RESOLVED 2026-09-29** (see §15.1 below).
2. ~~`ddos` false-positives on mDNS~~ — **RESOLVED 2026-09-29**: `_is_noise_traffic` is now
   applied inside `rules.ddos` before any volume judgement, so service-discovery chatter can
   never be scored as reflection amplification. 38 of 41 historical mDNS FPs are gone.
3. `confidence` is a fixed constant for 3 of 6 classes (`0.8` for recon/exfil-without-ML, `0.7`
   for encrypted) — severity is therefore a label, not a measurement. The C2 and DDoS rules now
   emit graded confidences, but the rest are still binary.
4. Old false alerts persist in the append-only store by design. `rm artifacts/sentinel.db*`
   for a clean slate; the chain regenerates.
5. `AlertStore.__init__` resolves `ALERT_DB` at construction rather than as a default argument
   (fixed 2026-09-29). A default arg froze the value at *import* time, so a later `os.environ`
   change silently kept writing to the previous file — which is how the new API tests
   initially polluted the real `artifacts/sentinel.db` with a `test-v1` fixture row. That row is
   still in the store; a clean DB removes it.

---

## 16. Infrastructure

### Dockerfile
`python:3.11-slim` → `pip install -r requirements.txt` → `python models/train_models.py` (models
are trained **at build**) → `useradd sentinel` (uid 1000) → `USER sentinel` →
`CMD uvicorn api.main:app`.

### docker-compose.yml

| Service | Image / build | Ports | Hardening | Limits |
|---|---|---|---|---|
| `redis` | `redis:7.4-alpine`, appendonly, `save 60 1`, healthcheck `redis-cli ping` | none (not exposed) | `no-new-privileges` | — |
| `api` | build `.` | `8000:8000` | `read_only`, `tmpfs /tmp`, `cap_drop: ALL`, `no-new-privileges` | 256 M / 0.50 CPU |
| `worker` | build `.`, `python -m engine.stream_consumer` | none | same | 512 M / 1.00 CPU |
| `trainer` / `evaluator` | profile `tools` | none | same, `user: "0:0"` (to write the bind-mounted model artifact) | — |

Volumes: `./artifacts:/data` (`ALERT_DB=/data/sentinel.db`), `./models/artifacts:/data/models`
(`MODEL_DIR`), `redis-data`.

⚠️ Gotcha: `trainer`/`evaluator` run as root **only** to write the bind mount, which leaves
root-owned files in `models/artifacts/`. Fix ownership afterward or the next non-root write fails.

### Make targets

```
generate      traffic-gen/generators/generate_scenarios.py
test          python3 -m unittest discover -s tests -v
check         compileall + docker compose config          (CI-style gate)
evaluate      run_evaluation.sh -> eval/results.{json,md}
loadtest      eval.loadtest -> artifacts/loadtest.{json,md}
train         docker compose --profile tools run trainer
model-eval    docker compose --profile tools run evaluator
demo          scripts/run_demo.sh        (full demo + evidence bundle)
judge-demo    scripts/run_judge_demo.sh  (best demo path: live capture proof + stream)
capture-proof scripts/run_end_to_end_capture_proof.sh
live-proof    scripts/run_live_capture_proof.sh
preflight     scripts/demo_preflight.sh  (compose config + /health poll)
evidence      scripts/export_evidence_bundle.sh
```

### Scripts

| Script | Role |
|---|---|
| `preview_server.py` | stdlib-only dashboard+API on `:8001` (single-threaded — see §10) |
| `run_pcap_replay.sh` | tcpreplay a PCAP into the `ntro-feed0` veth at a given Mbps |
| `run_zeek.sh` | run Zeek in the capture namespace |
| `setup_lab.sh` / `teardown_lab.sh` | create/destroy `ntro-capture` ↔ `ntro-replay` netns pair |
| `verify_one_way.sh` | records addr/routes/IPv6/firewall/sockets + a **must-fail** egress test into `artifacts/zeek-live-<UTC>/` |
| `run_live_capture_proof.sh`, `run_container_live_lab.sh` | in-container netns + `nft OUTPUT DROP` + Zeek + tcpreplay, collecting environment evidence |
| `run_end_to_end_capture_proof.sh` | Mode A/B: capture proof → compose up → tailer → assert ddos/dga/recon non-empty → evidence bundle |
| `run_demo.sh` | generate → compose reset → paced replay of all 8 attack scenarios → evidence bundle |
| `run_judge_demo.sh` | live capture proof + streaming c2/encrypted/exfil → `artifacts/judge-demo-summary.json` |
| `run_evaluation.sh`, `run_replay.sh`, `demo_preflight.sh`, `export_evidence_bundle.sh` | eval / paced replay / readiness poll / evidence export |
| `tap/Dockerfile` | `zeek/zeek@sha256:7073…` pinned + iproute2, nftables, tcpreplay, iputils-ping |

---

## 17. Quick reference — verified commands

```bash
cd /home/arshlaan/Bedrock/SIH26

# Dashboard with zero deps (reads the live artifacts/sentinel.db)
python3 scripts/preview_server.py 8001        # -> http://127.0.0.1:8001

# One-shot file analysis into the store
python3 -m ingest.service --file capture.pcap --once
python3 -m ingest.service --file friday.csv --once        # CSV supported
MAX_PACKETS=300000 python3 -m ingest.service --file big.pcap --once

# Print detections without storing
python3 -m ingest.pcap_to_events <pcap> [max_packets]

# 24/7 live capture (root required; watch events_total actually grow)
sudo python3 -m ingest.service --live wlp0s20f3
sudo python3 -m ingest.service --live wlp0s20f3 --watch artifacts/inbox

# Full stack. Write endpoints are token-gated; compose REFUSES to start without the variable.
echo "SENTINEL_API_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> .env
docker compose up -d --build                            # -> http://localhost:8000
curl -s localhost:8000/health | python3 -m json.tool
curl -s localhost:8000/api/evidence/verify | python3 -m json.tool
curl -s -X POST localhost:8000/api/alerts -H "Authorization: Bearer $SENTINEL_API_TOKEN" \
     -H 'Content-Type: application/json' -d @alert.json

# Gates
make test && make evaluate && make check

# Health of the store, without the API
python3 -c "from alertstore.store import AlertStore as S; import json; \
  s=S(); print(json.dumps(s.summary(),indent=1)); print(s.verify_chain())"

# Is the ML active?
python3 -c "import json,sklearn; \
  print('runtime',sklearn.__version__,'manifest',json.load(open('models/artifacts/training_manifest.json'))['scikit_learn_version']); \
  from models.inference import dga_score; print('dga_score ->',dga_score('xk39fjq2mzp1vb7wnt'))"
```

---

## 18. Verified session state (2026-09-29 12:03 UTC snapshot)

| Item | Value |
|---|---|
| Tests | `108/108` pass, 0 skips (13 feature · 2 CSV · 24 C2-structure · 8 recon-fanout · 16 model/exfil/encrypted · 7 model-integrity · ~26 contract/security negative · 9 API auth) |
| Eval | `8/8` attack scenarios, benign alerts `0`, FPR `0.0`, DDoS subtypes `3/3` |
| Hash chain | `valid: true` |
| ML | **inactive** (artifacts `sklearn 1.6.0` vs runtime `1.8.0`) |
| Running processes | `preview_server.py :8001` (pid 83772, since 11:39) · `ingest.service --live wlp0s20f3` (pid 97911, since 12:01 — post-fix code) |
| Store | 468 alerts at snapshot time; `c2_beaconing` 437 is **cumulative history** including ~430 pre-fix false positives; only alerts after the 12:01 restart reflect the fixed rules. ⚠️ Live capture is still running, so alert counts keep climbing — treat the numbers here as a snapshot, not a live figure, and re-run §17's health command for current values. |
| Interface | `wlp0s20f3` UP, `172.168.1.142/22`, routes via `172.168.0.1` |
| Git | `1670e67` pushed to `origin/main`; author set to `dr4cule <dr4cule@users.noreply.github.com>` (noreply) |

---

## 19. Security posture (hardened 2026-09-29)

Reviewed a 28-item security/quality report; the findings that were real and the fixes applied:

| Area | Change | File |
|---|---|---|
| Unauthenticated writes | `POST /api/alerts` and `POST /api/ingest` require `Authorization: Bearer $SENTINEL_API_TOKEN`, constant-time compared, **fails closed** (503) when unset. Compose refuses to start without it. Reads stay open. | `api/auth.py`, `api/main.py`, `docker-compose.yml` |
| Unbounded upload memory | Body is streamed to disk in chunks and aborted at the cap. Cap lowered from an unreachable 300 MB to **100 MB** (under the api container's 256 M limit). 413 instead of OOM. | `api/main.py`, `ingest/service.py` |
| `confidence=True` accepted | `bool` subclasses `int`; boolean confidence now rejected explicitly, plus strict numeric range. | `engine/validation.py` |
| Unbounded correlation re-fire | 3600 s per-source cooldown; a noisy source now yields 1 correlated alert, not one per event. | `correlation/engine.py` |
| Pickle RCE via `MODEL_DIR` | SHA-256 sidecar in the training manifest, verified (streamed) before any unpickle; missing digest fails closed. | `models/inference.py`, `models/train_models.py` |
| WS cross-site handshake | Origin compared to `Host`; mismatched origin closes with `1008`. | `api/main.py` |
| `ALERT_DB` frozen at import | Resolved in `__init__` instead of as a default argument. | `alertstore/store.py` |
| Untested failure paths | ~26 negative tests + 9 API tests; the chain is now proven to break on tamper/delete/reorder. | `tests/test_contracts_and_security.py`, `tests/test_api_auth.py` |

Findings that were **not** acted on, with reasons: `F-01` (the cited starlette version is not
pinned in this repo and the advisory count was unverified; a hash-pinned lockfile is still worth
adding), `F-03` (WS is read-only), `F-04`/`F-11` (the watcher already funnels through the single
consumer; the documented upload-vs-worker race lives only in `ingest_upload`), `F-12` (verify is
on `/health` and the dashboard's 5 s poll, not the 1 Hz WS loop), `F-13` (measured 0.6–1.7 ms
per call), `F-15` (measured 20.9 ms per 1000 adds at `max_keys`), `F-16` (`qr==0` is already
checked), `F-22` (standard `BUSYGROUP` idiom), `F-25` (environment is already recorded),
`F-26`/`F-28` (cosmetic).

**Not yet done:**
- `GET /api/alerts` and the dashboard remain unauthenticated by design (read-only enclave).
- `docker-compose.yml` still bind-mounts `./artifacts` read-write, so `read_only: true` on the
  container root does not extend to the data path.
- `scripts/preview_server.py` has no auth at all (stdlib-only dev server) and remains
  single-threaded.

## 20. Second hardening pass (2026-09-29) — F-06, F-10, F-24, exfil ranking

| Finding | Status | Change |
|---|---|---|
| **F-06** train/eval shared benign vocabulary | FIXED | New `models/holdout.py` owns both lists; they are now disjoint in **vocabulary** and in the DGA generative process (lengths 12–27, not just 18). `models/evaluate_models.py` rebuilds the holdout and records `benign_vocabulary_disjoint_from_training`. |

**The F-06 result is the important part.** On the leaked split the starter DGA classifier
reported precision/recall/F1 = 1.00. On the honest split it reports **0.32 / 1.00 / 0.48**, with
255 of 270 held-out benign labels predicted DGA. Diagnosis: the model learned **token length,
not entropy** — `grafana` (7 chars) scores 0.82 while the memorised training words score ~0.12.
The 1.0 was measuring memorisation.

This is recorded rather than tuned away. The lexical gate in `detectors/rules.py` is the real
DGA detector; the ML is second-opinion enrichment that degrades to `None` when its version or
digest gate fails. `models/model_cards/README.md` carries a prominent warning that the committed
`dga_holdout_evaluation.json` is stale and must not be quoted. (It cannot currently be
overwritten: `models/artifacts/` is root-owned from the `trainer` Docker profile, which runs as
uid 0 to write the bind mount. `sudo chown $(id -u):$(id -g) models/artifacts/*` then
`make model-eval` regenerates it.)

| Finding | Status | Change |
|---|---|---|
| **F-10** `encrypted_malware` dead without JA3 | FIXED | A metadata-only fallback fires when the scapy/live path has no fingerprint. It requires **three** independent anomalies to agree (upload asymmetry, low host diversity, unattributable destination) and scores `0.5` vs `0.7` for a real JA3 match, so it ranks below the strong path. A provider destination is excluded. |
| **exfil** live FPs | FIXED | Same ASN reputation ranking as C2: a sustained upload to a provider/CDN host becomes `0.5/medium` instead of `0.8-0.9/high`. Never suppressed. 21 consecutive Cloudflare alerts would all have downgraded. |
| **F-24** `read_only` defeated by rw bind mount | PARTIAL — see note | Mounting `/data` `:ro` is **impossible**: it *is* the alert store. What is available on a write mount is now applied — `:nosuid,nodev,noexec` on all four bind mounts, and the reason is documented inline. |

**F-09 is still open, deliberately.** The C2 rule still skips RFC1918/CGNAT destinations, so
lateral C2 to `10.x` / `192.168.x` / `100.64.x` is invisible. That gate is load-bearing:
`experiments/datasets.yml` records that removing it on real enterprise traffic produced a
118-alert false-positive storm. It needs a second signal (host-role, port profile, DNS context)
before it can be loosened safely.

## 21. Suggested next steps, in priority order

Items 1–3 below are **done** (see §15.1, §20); the list is retained so the reasoning behind
each fix stays discoverable.

1. ~~Apply `_is_noise_traffic` to `rules.ddos`~~ — **DONE**, mDNS suppressed before any volume
   judgement, 38 of 41 historical FPs removed.
2. ~~Destination reputation / allowlist layer for C2~~ — **DONE** as an ASN-based *ranking*
   layer (`detectors/reputation.py`), deliberately not a hard allowlist, so an implant on a CDN
   IP still surfaces at a lower score.
3. ~~Give `encrypted_malware` a metadata-only fallback~~ — **DONE**, three-signal heuristic
   scored below the JA3 path.
4. **Replace the remaining fixed confidences.** `recon` and `exfil`-without-ML still emit `0.8`
   and `encrypted` `0.7` regardless of how extreme the features are, so the dashboard's
   confidence histogram carries little information for those classes.
5. **Zeek Tier-A validation with a real labeled PCAP** and an IP+time+port label join — the
   only path to a legitimate external precision/recall number.
6. **Retrain the DGA model on real, family-separated public labels** (dns-zen, DGArchive) with
   per-family splits. The current 0.48 F1 is honest but weak, and the root cause is known: it
   learned length, not entropy (§20).
7. **Hash-pinned lockfile** (`pip-compile --generate-hashes`) plus a `pip-audit` CI step, rather
   than the unverified version numbers in the original review.
8. **Multi-worker HTTP server in `preview_server.py`** to eliminate the single-threaded wedge (§10).
9. **F-09 (lateral C2):** loosen the RFC1918/CGNAT skip only alongside a second signal —
   host-role, port profile or DNS context. Never on its own; §20 explains the 118-alert storm.
