# Features and model approach

Sentinel does not retain packet payloads. It consumes only passive metadata from Zeek or the replay schema.

| Class | Bounded state / features | Fast path | ML / adaptive contribution |
|---|---|---|---|
| DDoS | 5 s destination window, SYN/UDP rate, unique sources, source entropy, completion ratio, byte asymmetry | SYN, reflection and spoof-like topology rules | Reserved for a labelled subtype classifier after PCAP labels exist |
| C2 | 300 s source/destination window, IAT mean/CV, stable port, persistence | Low-jitter periodicity with duration guard | Clustering is a future extension; no unvalidated result is claimed |
| DGA/DNS | 60 s query-domain window, label length/entropy, unique subdomains, rate, qtype | Lexical and tunnel behavior rules | Character TF-IDF 2–5 gram Logistic Regression starter model |
| Encrypted | TLS version, SNI, JA3/JA4 when supplied by Zeek package, cipher, timing/bytes, visible certificate metadata | Metadata anomaly evidence; fingerprint is never a verdict | Feature-vector classifier is reserved for verified labels |
| Recon | 30 s source window, host/port fan-out, scan rate, failures | Horizontal/vertical fan-out | Optional anomaly confirmation later |
| Exfiltration | 300 s conversation window, upload total, upload/download ratio, persistence | Robust fixed safety threshold | Isolation Forest starter baseline; no external metric claimed |

## Training discipline

`make train` builds two compact artifacts in `models/artifacts/` and writes `training_manifest.json` with the exact scikit-learn version. Inference refuses an artifact built under a different scikit-learn version, then falls back to the explainable rule. This prevents silently loading incompatible model binaries.

`make model-eval` retrains and writes `models/artifacts/dga_holdout_evaluation.json` from a disjoint generated-lab lexical holdout. This result is machine generated and reproducible, but explicitly scoped to generated labels—not a claim about real-world malware/DGA detection.

The committed training examples are generated lab labels solely to prove the reproducible train/load/inference path. Before a final accuracy claim, train/validation/test partitions must be separated by host/session/date for traffic and by DGA family for domains; save class balance, PR curves, confusion matrices, calibration and model SHA-256 with the resulting model card.
