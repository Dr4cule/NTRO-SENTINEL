# Interesting Stuff — NTRO Sentinel context & decision log

> Handoff document. Read this and you have the whole project: what it is, how every
> stage works, and — most importantly — **why** each non-obvious decision was made.
> Written for a fresh agent (or human) picking this up cold.

---

## 0. What this is, in one breath

**Sentinel** is a passive, payload-blind, one-way network **threat-detection pipeline** built for
SIH 2026 problem statement **26145 (NTRO)**: *"AI-based detection of cyber threats in
unidirectional IP traffic."* It watches a *copy* of network **metadata** (never packet
contents), runs six deterministic detectors over bounded time windows, correlates the
alerts per source, stores them in a tamper-evident log, and streams them to a live
dashboard.

Data flow, end to end:

```
Zeek (sensor) → Redis Streams (buffer) → feature windows → 6 detectors
   → correlation → SQLite hash-chained store → FastAPI + WebSocket → dashboard
```

---

## 1. The non-negotiable principles (these constrain EVERYTHING)

Every design choice below descends from these. If you change code, do not violate them.

1. **Passive / payload-blind.** We only ever read metadata: IPs, ports, byte counts,
   timings, DNS query *names*, TLS *fingerprints*. Never payload bytes. `detectors/rules.py`
   opens with `# No payload fields are consumed.` — keep it that way.
2. **One-way.** The monitor can only *receive* a mirrored copy of traffic. It must never
   emit anything back onto the monitored link. This is both the PS requirement and a
   safety property (the sensor can't become an attack vector).
3. **NEVER fabricate metrics.** This is the strongest rule in the project. No made-up
   precision/recall/F1. Every number is either measured by a committed script or not
   claimed at all. `PERFORMANCE.md` deliberately commits *no* figure. `eval/run_suite.py`
   computes honest scenario-level coverage + confusion + FPR and **explicitly refuses** to
   report flow-level F1. If you're tempted to print an impressive number, measure it or
   drop it.
4. **Enclave / no egress.** Runs air-gapped. No CDN, no external fonts, no outbound calls
   at runtime. That's why the dashboard is one self-contained HTML file with an inlined
   base64 logo and system fonts (see §10).
5. **Deterministic & explainable.** Detectors are plain thresholds, not a black box, so
   every alert can be justified field-by-field. Critical for a government/intelligence
   audience.
6. **Bounded everything.** Memory and render paths are capped so massive traffic can't
   OOM the worker or make the UI unusable (see §8).
7. **Tamper-evident.** Alerts live in a hash chain; editing history breaks verification
   (see §9).

---

## 2. Architecture stage by stage (with real file names)

**Stage 1 — Zeek (the sensor).** `ingest/zeek/sentinel.zeek` tells Zeek what to emit.
Zeek watches a monitored interface and turns raw packets into one-line metadata records:
connection summaries (`conn`), DNS lookups (`dns`), TLS handshakes. It never stores payload.
`ingest/tailer.py` tails Zeek's logs and pushes records onto Redis.

**Stage 2 — Redis Streams (the buffer).** Decouples the fast sensor from the detectors and
absorbs bursts. Stream `telemetry`, consumer group `sentinel`. This is where backlog/lag/drops
become measurable. In dev you can bypass Redis entirely and replay a JSONL file (see §7).

**Stage 3 — Feature windows (short-term memory).** `features/*.py`, all built on
`features/base.py::WindowState` — a bounded, timestamp-keyed rolling window. From recent
events per key it computes the numbers detectors need: distinct dst ports (recon), inter-
arrival regularity (beacon), DNS label entropy (DGA), byte ratios (encrypted/exfil).

**Stage 4 — The six detectors.** `detectors/rules.py`. Deterministic thresholds → an alert
dict or `None`. Full thresholds in §4.

**Stage 5 — Correlation.** `correlation/engine.py`. Groups alerts per source IP; when one
source trips ≥2 distinct threat classes it emits a `correlated_multi_signal` meta-alert.

**Stage 6 — Alert store.** `alertstore/store.py`. Append-only SQLite with a SHA-256 hash
chain (§9).

**Stage 7 — API + dashboard.** `api/main.py` (FastAPI) serves REST + a WebSocket that pushes
live updates; `dashboard/index.html` is the single-file UI (§10).

The orchestration lives in `engine/stream_consumer.py::Pipeline` (§7), driven either by the
Redis worker (deployed) or the JSONL runner (dev/eval).

---

## 3. The event & alert contracts

**Incoming telemetry event** (dict) carries e.g.: `kind` (`conn` | `early_event` | `dns`),
`ts` (float epoch), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `orig_bytes`,
`resp_bytes`, `conn_state`, `tcp_flags`, and for DNS `query`, for TLS `tls`/`tls_version`/
`sni`/`ja3`/`suspicious_fingerprint`. `early_event` = a partially-observed connection (e.g. a
lone SYN) — **we alert on these without waiting for the flow to complete**, which is the
whole point of streaming detection (guide "Failure 3": don't wait for completed flows).

**Alert record** (built by `engine/contracts.py::alert`, then validated by
`engine/validation.py`). Exact shape — the dashboard, store, and tests all depend on it:

```json
{ "alert_id": "uuid4", "timestamp": "...", "flow_id": {"src_ip","src_port","dst_ip","dst_port","proto"},
  "threat_class": "...", "subtype": "...", "confidence": 0.0-1.0, "severity": "low|medium|high|critical",
  "supporting_evidence": {...}, "mitre_attack": ["T…"], "model_version": "…" }
```

- **confidence** is a clamped, rounded *normalized detector score, NOT a calibrated
  probability* (said so in a code comment on purpose — honesty rule).
- **severity** is derived from score: `≥.9 critical, ≥.7 high, ≥.45 medium, else low`.
- **model_version** is a per-rule string (`ddos-rules-v1`, `dns-lexical-ml-v1`, …) so every
  alert is traceable to the exact logic that produced it.

---

## 4. The six detectors — exact logic & why

All in `detectors/rules.py`. Each returns an `alert(...)` or `None`. `aggregation_key` in the
evidence is what dedup and correlation group on (see §7).

| Class | Fires when | Subtype logic | MITRE | Keys on |
|---|---|---|---|---|
| **ddos** | `syn_count≥20` OR (`udp_count≥20` AND `unique_sources≥8`) | `udp_reflection_amplification` if UDP path; `spoof_like_source_flood` if `source_ip_entropy≥3.5`; else `syn_flood` | T1498 | `dst=<ip>` |
| **c2_beaconing** | `session_count≥4` AND `iat_cv≤.15` AND `persistence_seconds≥60` AND `destination_port_count≤2` | `periodic_beacon` | T1071.001 | `src|dst` |
| **dga_dns_tunnel** | (`label_length≥18` AND `label_entropy≥3.3`) OR ML `dga_score≥.8` | `dns_tunnel` if `query_rate≥.05` AND `unique_subdomains≥3` else `dga_domain` | T1071.004 / T1568.002 | src |
| **encrypted_malware** | `tls` AND (`outbound_inbound_ratio>8` OR `suspicious_fingerprint`) | `metadata_anomaly` | T1071.001 | flow |
| **recon_scan** | `unique_dst_ports≥12` OR `unique_dst_hosts≥12` | `vertical_scan` if ports≥hosts else `horizontal_scan` | T1046 | `src=<ip>` |
| **exfiltration** | `outbound_bytes≥500000` AND `outbound_inbound_ratio≥5` | `sustained_outbound_anomaly` | T1041 | `src|dst` |

Interesting bits:
- **ddos confidence scales**: `min(1,(syn+udp)/40)` — a bigger flood reads as higher
  confidence, so severity rises with intensity instead of being a flat constant.
- **UDP-reflection reasoning is commented in code**: a one-way monitor may only see the
  reflector→victim direction, so reverse-byte evidence can be missing; UDP volume + source
  diversity is still valid passive evidence in that direction. This is the kind of "designed
  for the one-way constraint" detail worth preserving.
- **DGA is hybrid**: a lexical rule (length+entropy) OR a learned char-ngram model. If the ML
  model is present the `model_version` becomes `dns-lexical-ml-v1`, else `dns-lexical-v1` —
  the alert self-documents whether ML was in play. The ML call is `models.inference.dga_score`.

---

## 5. Correlation — how "incidents" form

`correlation/engine.py::Correlator` keeps the last 8 alerts per `src_ip`. When a single source
has produced **≥2 distinct threat classes**, it emits one `correlated_multi_signal` alert
(confidence .85, 300s window) listing the `underlying_alert_ids` and the `classes`. Rationale:
a host doing recon *and* beaconing *and* exfil is one story, not three unrelated blips.

Note (factual, so you don't get surprised): the correlated meta-alert is emitted with
`threat_class="c2_beaconing"` / `subtype="correlated_multi_signal"`. It's guarded so it won't
re-emit for a source that already has one. The dashboard's **incidents** view is the
source-centric roll-up: `/api/incidents` groups alerts by src_ip, sums a risk score, and
(**as of the risk-sort fix**) returns them **highest-risk first** so the worst sources surface
even under massive traffic.

---

## 6. The streaming engine — `Pipeline.process`

`engine/stream_consumer.py`. One event in → list of fresh alerts out.

1. Route by `kind`: `conn`/`early_event` → ddos, c2, recon, exfil; `dns` → dga; `tls` present
   → encrypted. Each detector gets its feature-window update for this event.
2. **Dedup (30s):** key = `(threat_class, subtype, aggregation_key)`. An alert only fires if
   `≥30s` since that key last fired. Stops one ongoing flood/scan from spamming thousands of
   identical alerts while still re-alerting if the behavior persists. `self.emitted` holds the
   last-emit timestamp per key.
3. Return `fresh + correlation.process(fresh)`.

Two drivers wrap this:
- **`redis_worker()`** — the *deployed* path. Reads the Redis `telemetry` stream in a consumer
  group, processes, appends to the store, records `StreamMetrics` (p50/p95/p99 latency,
  throughput, lag), and `xack`s. This is "real" streaming, not batch.
- **`run_jsonl(source)`** — dev/eval path. Replays a JSONL scenario file straight through the
  same `Pipeline`, no Redis needed. This is what the tests and `eval/` use for determinism.

---

## 7. Bounded state & massive-traffic handling (intended, load-bearing)

The PS implies high traffic, so nothing is allowed to grow without a cap.

- **`WindowState` (features/base.py)** evicts two ways: **time** (drop entries older than the
  window) and **count** (`max_keys=4096`; when exceeded, drop the oldest-touched key). So a
  spoofed flood with millions of fake source IPs can't grow the state unbounded.
- **Dedup** (§6) bounds alert *volume* per behavior to ≤1 per 30s per key.
- **Dashboard** is built for "can't scroll forever":
  - The alert feed has a **search box** (matches ip / class / evidence), **class filters**, and
    **severity filters**.
  - It renders a **page of 60** with a **Load-more** button, and shows an honest
    `Showing N of M (most recent 250)` counter — the API caps at 250, so the UI never claims to
    show more than it has.
  - Every chart caps its own input: timeline ≤14 buckets, confidence 10 bins, distribution 6
    classes, **relationship graph = top 7 sources × top 7 destinations** (edges filtered to
    those nodes, so ≤49 edges no matter the load), hosts = top 6 by count, incidents = top 6 by
    **risk** (sorted server-side — see §5).

If you add a new view, keep this discipline: cap the input, sort by importance, paginate.

---

## 8. Storage & tamper-evidence — `alertstore/store.py`

Append-only SQLite (`artifacts/sentinel.db`, bind-mounted into containers). Each row stores
`record_hash = sha256(prev_hash + canonical_json(record))`, chaining every alert to the one
before it. `verify_chain()` walks rows in `seq` order recomputing hashes; any edit/reorder/
delete of past rows breaks it → surfaced at `/api/evidence/verify` and in `/health`.

Consequence to know: you **cannot** surgically delete a middle alert without breaking the
chain. Deleting from the *tail* keeps a shorter valid chain (that's how the two test alerts
injected during verification were safely removed). A full reset = wipe the DB and re-replay.

Also stores `telemetry_metrics` rows (throughput, lag, p50/p95/p99) written by the worker via
`StreamMetrics` (`engine/metrics.py`, 10k-latency ring buffer).

---

## 9. The dashboard — decisions

`dashboard/index.html`, single self-contained file, served by FastAPI at `/`.

- **Vanilla by choice, not by limitation.** No framework, no build step, zero npm deps. In an
  air-gapped, audit-heavy security context that's a *feature*: nothing to vet but one readable
  file, and it matches the project's reproducibility ethos. It still uses modern *techniques*
  (CSS custom properties, grid, WebSocket, hand-rolled SVG charts). A framework (Svelte/React)
  is feasible in the enclave *if* fully bundled with no runtime external calls — but it's not
  necessary here and adds supply-chain surface. Revisit only if this grows into a large
  multi-page app.
- **Neo-brutalist visual system** (current): 0-radius corners, ~2px true-black borders, hard
  offset shadows (no blur/glass), flat white blocks on paper, heavy display numerals. It was
  converted from an earlier glass style by **redefining the `.glass` token's meaning**, not by
  renaming every element — minimal diff, same render logic.
- **Six semantic threat colors** are fixed and validated: ddos/c2/dns/enc/recon/exfil each own
  a hue; keep them stable so the timeline, graph, and chips stay legible.
- **Logo + favicon are inlined base64** (no egress). The brand mark sits in a black box that
  matches the logo's dark background.
- **Seven views**: live feed + detail drawer, timeline, threat distribution, confidence
  histogram, source→destination graph, top hosts, correlated incidents.
- **Live wiring**: `load()` does `Promise.all` over the REST endpoints; a WebSocket pushes new
  alerts; `setInterval(load, 5000)` is the fallback refresh. Don't break these when editing.

Deploy note: the dashboard is **baked into the api Docker image** (no volume mount), so after
editing it you must `docker compose up -d --build api` to see it on `:8000`. The standalone
preview server (`scripts/preview_server.py`) reads the HTML once at startup → restart to refresh.

---

## 10. Evaluation & the honesty machinery

Three committed evaluators, all deliberately non-inflationary:

- **`eval/run_suite.py`** (controlled scenario coverage). Replays each committed scenario
  through the pipeline and reports: which attack scenarios were detected (target class
  appeared), a **confusion matrix** (scenario truth × predicted class), **benign
  false-positive rate**, and **alert-level precision** per class. It writes a prominent note:
  *"Flow-level recall/F1 is intentionally not claimed"* — because the scenarios are
  homogeneous, one aggregated alert can cover many flows, so a flow-level F1 would be a lie.
  Verified state: 8/8 attack scenarios detected, benign FPR **0.0**, precision 1.0, 3/3 ddos
  subtypes. Outputs `eval/results.{json,md}`.
- **`eval/loadtest.py`** (processing envelope). Closed-loop rate sweep: replays telemetry at
  rising target rates, measures achieved flows/sec, Mbps, drops, p50/p95/p99 latency, CPU,
  peak RSS, and reports the **highest *stable* rate** (`≥95%` of offered sustained, `<1%`
  drops — the <1% tolerates generator jitter). Loudly labeled **NOT a PCAP Mbps benchmark**.
  ~5000 flows/sec on the dev box. Outputs `artifacts/loadtest.{json,md}`.
- **`eval/cic_ids2017_coverage.py`** (dataset fit check — see §12). Reads a real CIC-IDS2017
  release and reports, field by field, whether each detector can even run on it. Makes **no**
  P/R/F1 claim.

**Tests**: `tests/test_features.py`, 11 cases — window eviction (count + time), DNS entropy
benign-vs-DGA, TLS benign ratio, recon alert, all six detection paths, ddos subtypes + alert
contract shape, **benign raises zero alerts (FPR guard)**, dedup suppresses repeats within 30s,
eval confusion clean + FPR zero, loadtest envelope sane.

---

## 11. Data & how to test with real traffic

**Sentinel needs raw packets (PCAP), not pre-computed flow features.** Zeek watches packets;
it can't consume a table of statistics.

Is PCAP *enough*? Depends on the goal:
- **See it work** → one relevant PCAP is enough (replay → Zeek → alerts on the dashboard).
- **Prove how well it works (P/R/F1/FPR)** → you also need: **ground-truth labels** (join the
  dataset's label CSV back onto alerts by 5-tuple+time), **protocol variety** (DNS records for
  the DGA detector, TLS handshakes for encrypted — a bare-TCP PCAP won't exercise those), and a
  **benign capture** for false-positive rate. All six classes likely span **several** PCAPs.

Three evidence tiers (build guide §2):
- **Tier A (required):** paced PCAP replay → `scripts/run_pcap_replay.sh <pcap> [mbps]`
  (tcpreplay into a monitored veth in a network namespace → live Zeek). This is the primary
  reproducible proof.
- **Tier B (recommended):** lab-generated traffic. `make generate` builds safe synthetic PCAPs
  via `traffic-gen/generators/generate_pcaps.py` (scapy: `safe_syn_flood`, `safe_udp_reflection`,
  `safe_dns_tunnel`, `safe_recon`, `safe_mixed`) with correct IP/port/DNS metadata + `.sha256`.
  Also generates JSONL metadata scenarios (`generate_scenarios.py`) for the deterministic tests.
- **Tier C (optional):** live mirrored/TAP traffic.

**Offline substitute (when Zeek + tcpreplay aren't installed).** The sanctioned path is Zeek, but
two components let a real `.pcap` — or live traffic — drive the pipeline without it:
- `ingest/pcap_to_events.py` — payload-blind PCAP→events adapter. Streams packets (scapy
  `PcapReader`), assembles L3/L4 headers into Zeek-like `conn`/`dns` events matching
  `ingest/tailer.py`'s schema (flow byte totals, `conn_state`, `history[:1]`, DNS query names).
  Reads headers + DNS question names only; byte counts are payload *lengths*, never content.
- `ingest/service.py` — **24/7 ingest service**. One consumer thread is the *sole* store-writer
  (keeps the hash chain serialized) fed by a queue; sources run together: `--live IFACE`
  (scapy `AsyncSniffer` + streaming flow cache, needs root/CAP_NET_RAW), `--watch DIR` (drop-in
  `.pcap`/`.jsonl`/Zeek-json, moved to `processed/` after), `--file PATH` (`--once` = ingest & exit).
  Writes to the same `artifacts/sentinel.db` the API reads, so alerts appear on the dashboard live.

  Honest caveats: bounded sample (7.8 GB won't fully parse in scapy); no label join → **behavioral,
  not scored**; `encrypted_malware` isn't exercised (no JA3 derived offline). Verified on
  CIC-IDS2017 Thursday: pipeline runs end-to-end, but the sampled window is pre-attack normal
  traffic, so alerts are heuristic **false positives** (browsing→recon, CDN names→DGA) — see
  the `cic-ids2017-thursday-pcap` entry in `experiments/datasets.yml`.


Good public sources for Tier A: **CIC-IDS2017 PCAPs** (raw captures, not the flow CSV/parquet),
**CTU-13** (botnet, great for c2), **malware-traffic-analysis.net** (small labeled real malware).

`experiments/datasets.yml` is the dataset registry — every real dataset gets an entry with
source, license, label mapping, and a **verified** coverage result (never copied from a paper).

---

## 12. The CIC-IDS2017 finding (a worked example of the honesty rule)

The dataset dropped at `~/Downloads/archive` is the **de-identified CICFlowMeter flow-feature
release**: 8 parquet files, **2,313,810 flows**, 78 statistical columns + `Label`. It has
**zero** connection metadata — no IP, port, DNS query, TLS fingerprint, or timestamp. Only
`Protocol` and byte totals are usable.

Verdict (measured by `eval/cic_ids2017_coverage.py`, recorded in `experiments/datasets.yml`):
**none of the six detectors can run on it**, because Sentinel keys on exactly the metadata this
release strips. This is not a phase failure — it's the wrong *artifact*. To validate detectors
on CIC-IDS2017 you need its **PCAPs**, replayed through Zeek (Tier A). The takeaway to carry
forward: verify a dataset against the actual pipeline before claiming coverage; don't fabricate
a mapping to force a number.

---

## 13. ML models — prototypes, honestly scoped

`models/` holds two small, explainable models trained on **synthetic/lab** data:
- **`dga_char_ngrams.joblib`** — char n-gram TF-IDF → LogisticRegression, benign-vs-DGA domain
  strings. Called from the DGA detector via `models.inference.dga_score`.
- **`exfil_baseline.joblib`** — IsolationForest on `[bytes, ratio]`.

`models/train_models.py` and `models/evaluate_models.py` both stamp a manifest with the seed,
sklearn version, and the warning *"No public-dataset performance is claimed."* The holdout eval
is a **reproducibility** check on a disjoint synthetic set (different seed), not a real-world
claim. Replace inputs with documented public/lab data before publishing any model metric.

---

## 14. Deployment & Docker (`docker-compose.yml`)

- **redis** — 7.4-alpine, appendonly, healthchecked.
- **api** — FastAPI + dashboard. `read_only`, `cap_drop: ALL`, `no-new-privileges`, tmpfs
  `/tmp`, 256M/0.5cpu, port 8000. Dashboard is baked into the image.
- **worker** — `python -m engine.stream_consumer` (the Redis streaming consumer).
  `read_only`, `cap_drop: ALL`, 512M/1cpu, waits for redis healthy.
- **trainer / evaluator** — `profiles: ["tools"]` (only run via `make train` / `make model-eval`).

**Gotcha worth remembering:** trainer/evaluator run as `user: "0:0"` (root) **only** so they can
write the bind-mounted `./models/artifacts` directory — this is commented in the compose file.
Side effect: the model artifacts on the host end up **root-owned**, so re-running
`python3 models/train_models.py` as your normal user fails with `PermissionError`. That's not a
bug in the code — use the Docker path, or `chown`/remove the artifacts first. Also: artifacts
were pickled with sklearn 1.6.0 (pinned in the image); loading under a newer host sklearn prints
an `InconsistentVersionWarning` — harmless, but train inside the image for a clean match.

Hardening lives in `docs/ENCLAVE_HARDENING.md`; one-way boundary proof scripts are
`scripts/verify_one_way.sh`, `run_live_capture_proof.sh`, `run_end_to_end_capture_proof.sh`.

---

## 15. Decision register (the "why", condensed)

- **No fabricated metrics** — `PERFORMANCE.md` commits no number; eval refuses flow-level F1.
  *Why:* credibility with NTRO judges; a caught exaggeration sinks the whole submission.
- **Honest eval = coverage + confusion + benign FPR + alert-level precision**, not F1.
  *Why:* homogeneous scenarios make flow-level recall meaningless; report only what's true.
- **Deterministic threshold detectors over an ML classifier** for the core path. *Why:*
  explainability and auditability beat a marginal accuracy bump for this audience.
- **Alert on `early_event`s, don't wait for completed flows.** *Why:* it's the difference
  between real streaming detection and mislabeled batch analysis (guide "Failure 3").
- **30s dedup keyed by (class, subtype, aggregation_key).** *Why:* one flood shouldn't emit
  thousands of identical alerts, but persistence should still re-alert.
- **Bounded `WindowState` (time + max_keys).** *Why:* spoofed source floods must not OOM state.
- **Server-side risk-sort on `/api/incidents`.** *Why:* under massive traffic the top-6 shown
  must be the *worst* sources, not the first-seen; fixing it server-side fixes every consumer.
- **Massive-traffic UI = search + class/severity filters + 60/page + Load-more + capped charts.**
  *Why:* "I can't scroll forever to find things." Every view caps input and sorts by importance.
- **Neo-brutalist by redefining `.glass`, not renaming elements.** *Why:* restyle with a minimal
  diff and zero risk to live render logic.
- **Vanilla, single-file, zero-dep dashboard + inlined logo/fonts.** *Why:* enclave has no
  egress; zero deps = zero supply-chain audit surface; one readable file matches the audit ethos.
- **Benign scenario includes real DNS + TLS negatives** (added at the *generator*, so it
  survives `make generate`). *Why:* proves FPR=0 against inputs that *could* trip the DGA/
  encrypted detectors, not just trivial traffic.
- **Hash-chained alert store.** *Why:* forensic tamper-evidence; you can prove history is intact.
- **trainer/evaluator as root, profile-gated.** *Why:* only way to write the bind-mounted model
  dir; kept out of the default runtime. (Accept the root-owned-artifacts side effect — §14.)
- **CIC-IDS2017 coverage recorded honestly as "no detector runnable" for the flow-feature
  release.** *Why:* the coverage matrix must reflect the real artifact, never a paper's claim.

---

## 16. How to run everything

```bash
make generate     # build safe synthetic PCAPs + JSONL scenarios
make test         # unit tests (11)  ·  or: python3 -m unittest tests.test_features
make evaluate     # controlled coverage + confusion + FPR → eval/results.{json,md}
make loadtest     # processing envelope → artifacts/loadtest.{json,md}
make train        # (docker, profile tools) train the prototype models
make model-eval   # (docker) honest holdout eval of the DGA model
make check        # compileall + docker compose config  (the CI-ish gate)

docker compose up -d --build            # redis + worker + api
docker compose up -d --build api        # rebuild ONLY api after editing the dashboard
curl localhost:8000/health              # status + chain validity + pipeline metrics
curl localhost:8000/api/evidence/verify # hash-chain verification

scripts/run_pcap_replay.sh <pcap> [mbps]                 # Tier A live replay
python3 -m eval.cic_ids2017_coverage --dir <archive_dir> # dataset fit check

# Offline ingest (no Zeek/tcpreplay) — writes to the dashboard's store:
python3 -m ingest.service --file capture.pcap --once           # one-shot: populate dashboard, exit
MAX_PACKETS=300000 python3 -m ingest.service --file big.pcap --once   # cap packets on huge files
python3 -m ingest.service --live eth0 --watch artifacts/inbox  # 24/7: live capture + drop-in files
python3 -m ingest.pcap_to_events <pcap> [max_packets]          # replay + print detections (no store)
```

---

## 17. Repo map

```
ingest/       Zeek script + log tailer; pcap_to_events.py (offline PCAP adapter) + service.py (24/7 live/file ingest)
features/     bounded feature windows (base.py = WindowState) + per-class feature extractors
detectors/    rules.py — the six deterministic detectors
correlation/  engine.py — per-source multi-signal correlation
engine/       stream_consumer.py (Pipeline + redis_worker + run_jsonl), contracts, validation, metrics
alertstore/   store.py — hash-chained SQLite
api/          main.py — FastAPI REST + WebSocket, serves the dashboard
dashboard/    index.html — the single-file UI
models/       train/evaluate/inference for the prototype ML models
eval/         run_suite.py, loadtest.py, cic_ids2017_coverage.py
traffic-gen/  generators for safe PCAPs and JSONL scenarios + the scenarios themselves
experiments/  datasets.yml (registry), scenarios.yml (labels)
scripts/      replay / live-capture / one-way-proof / demo shell scripts
docs/         DATASETS, DEMO_SCRIPT, ENCLAVE_HARDENING, LIMITATIONS, mitre_mapping, etc.
artifacts/    generated outputs + sentinel.db (bind-mounted into containers)
```

---

## 18. Known limits / honest gaps (don't overclaim)

- **No external-network throughput benchmark** is claimed. `loadtest` is an in-process envelope;
  real Mbps proof requires the live Zeek + tcpreplay path with recorded environment details.
- **Detectors are unproven on external labeled PCAP** so far — the committed evidence is
  controlled scenarios. Run Tier A with a labeled PCAP for real precision/recall.
- **ML models are synthetic-data prototypes**, explicitly not real-world classifiers.
- **The downloaded CIC-IDS2017 (flow-feature) release cannot drive the detectors** — need PCAPs.
- **One-way boundary** is demonstrated by lab scripts, not a hardware diode.

*Golden rule if you extend this: measure it or don't claim it, and keep the pipeline
payload-blind and one-way.*

