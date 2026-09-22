# Submission readiness checklist

| Item | Repository evidence | Status |
|---|---|---|
| Passive / one-way lab boundary | Host scripts plus Docker-contained namespace artifact | Live validated in disposable Docker lab; software approximation only |
| No decryption / payload retention | `ingest/tailer.py`, feature modules, data contracts | Implemented and source-checked |
| Incremental telemetry | Zeek tailer → Redis Streams → worker | Live Zeek replay and Docker worker validated |
| Six detection paths | `features/`, `detectors/`, generated controlled scenarios | Unit/evaluation validated |
| DDoS subtypes | `ddos`, `ddos_udp_reflection`, `ddos_spoof` scenarios | Controlled subtype tests validated |
| Standard alerts | `engine/contracts.py`, `engine/validation.py`, schema JSON | Unit validated |
| Live dashboard | FastAPI, WebSocket, `dashboard/index.html` | Docker/API validated |
| Evidence integrity | SQLite SHA-256 chain + `/api/evidence/verify` | Docker validated |
| ML train/load/evaluate path | `make train`, `make model-eval`, manifest/model cards | Docker validated with disjoint generated-lab holdout; limitations documented |
| Controlled evaluation | `make evaluate` → `eval/results.json`, `eval/results.md` | Validated; not an F1 claim |
| Synthetic load harness | `make loadtest` → `artifacts/loadtest.json` | Validated; not PCAP/Mbps proof |
| Paced PCAP + live Zeek | `make capture-proof`, Zeek policy, `artifacts/zeek-live-*` | Validated with checksummed safe lab PCAP, live Zeek 9.0 and tcpreplay |
| Final throughput/latency numbers | `PERFORMANCE.md`, live proof environment + pipeline summary | Live proof artifacts generated; external/public-PCAP benchmark still optional |

## Before final submission

1. Optionally add a permitted public PCAP and its provenance/labels/SHA-256 to `experiments/datasets.yml` for broader validation.
2. Run multi-rate duration tests if you want an external/public-PCAP throughput headline; retain raw commands and artifacts.
3. Replace or supplement starter training labels with group-separated documented inputs before making external ML accuracy claims.
4. Include `eval/results.json`, `artifacts/zeek-live-*`, evidence-bundle, model manifest and evidence-chain verification in the submission package.

Everything above is deliberately phrased as either implemented/validated or waiting for an external prerequisite. The latter must remain visible to judges; it is more credible than fabricated performance claims.
