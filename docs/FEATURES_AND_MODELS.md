# Features and model approach

Sentinel does not retain packet payloads. It consumes only passive metadata from Zeek or the replay schema.

| Class | Bounded state / features | Fast path | ML / adaptive contribution |
|---|---|---|---|
| DDoS | 5 s destination window, SYN/UDP rate, unique sources, source entropy, completion ratio, byte asymmetry | SYN, reflection and spoof-like topology rules, with service-discovery traffic suppressed first | Reserved for a labelled subtype classifier after PCAP labels exist |
| C2 | 300 s source/destination window, IAT mean/CV, stable port, persistence, mean bytes in **both** directions | Low-jitter periodicity **plus** three structural gates: direction (a beacon is a client request, not a response to an ephemeral port), size (a heartbeat is small both ways), and destination-ASN reputation. Reputation **ranks** — known-provider traffic becomes `periodic_session/medium`, unknown stays `periodic_beacon/high` | Clustering is a future extension; no unvalidated result is claimed |
| DGA/DNS | 60 s query-domain window, label length/entropy, unique subdomains, rate, qtype | Lexical and tunnel behavior rules | Character TF-IDF 2–5 gram Logistic Regression starter model. Second opinion only, never the gate |
| Encrypted | TLS version, SNI, JA3/JA4 when supplied by Zeek package, cipher, timing/bytes, visible certificate metadata | Fingerprint match is the strong path. When **no JA3 is available** (the scapy/live path), a metadata-only fallback fires on three agreeing anomalies: upload asymmetry, low host diversity, unattributable destination — scored below the fingerprint path | Feature-vector classifier is reserved for verified labels |
| Recon | 30 s source window, host/port fan-out, scan rate, failures | Horizontal/vertical fan-out, gated on failure ratio so browser CDN fan-out is not a scan | Optional anomaly confirmation later |
| Exfiltration | 300 s conversation window, upload total, upload/download ratio, persistence | Robust fixed safety threshold, plus destination-ASN reputation ranking (a sustained upload to a provider host scores `medium`, never suppressed) | Isolation Forest starter baseline; no external metric claimed |

## Why the C2 rule is not a metronome

Low-jitter periodicity alone cannot separate malware phone-home from a browser keepalive, an
IMAP IDLE stream, or a push channel — all four produce "N sessions, tiny CV, one port, sustained
for minutes". Measured on a live capture (`wlp0s20f3`, 2026-09-29), a pure timing rule produced
**630 alerts of which essentially all were GitHub / Google / Cloudflare / Amazon / WhatsApp
traffic**. A detector that fires on WhatsApp is not a detector.

The fix is additional independent evidence, not a looser threshold. The destination network is
resolved to an **autonomous system** from a committed, air-gapped prefix table
(`detectors/reputation.py`, `detectors/asn_prefixes.json`) and used to *rank*, never to suppress:
`reputation()` has no `'benign'` return value, so a missing table or an unresolvable address
falls to `unknown`, which is the loud class. A missing table must never make a detector quieter.

Note that `443` is deliberately **excluded** from the long-idle-port list: it is the primary
malware C2 port, so downgrading it automatically would bury genuine implants. An `https/443`
beacon to an unattributable host still lands at `high`.

## Training discipline

`make train` builds two compact artifacts in `models/artifacts/` and writes `training_manifest.json` with the exact scikit-learn version **and a SHA-256 digest per artifact**. Inference refuses an artifact whose digest or scikit-learn version does not match, then falls back to the explainable rule. This prevents silently loading incompatible *or tampered* model binaries — a joblib file is a pickle, so loading one executes it.

`make model-eval` retrains and writes `models/artifacts/dga_holdout_evaluation.json` from a holdout that is **disjoint in benign vocabulary** from the training set (`models/holdout.py`) and varies the DGA label length. This result is machine generated and reproducible, but explicitly scoped to generated labels — not a claim about real-world malware/DGA detection.

### The measured result, and why it is low

On the **leaked** split (train and evaluation sharing one benign vocabulary) the starter DGA
classifier reported precision/recall/F1 = 1.00. That number was measuring memorisation. On the
disjoint holdout it reports **precision 0.32 / recall 1.00 / F1 0.48**, predicting DGA for 255 of
270 held-out benign labels.

Diagnosis: the model learned **token length, not entropy** — `grafana` (7 characters) scores
0.82, `sonarqube` (9) scores 0.84, while the memorised training words score ~0.12. Nothing in
the synthetic training data rewards learning the distinction.

This is reported rather than tuned away. A low honest number is more useful than a high
flattering one, and the lexical gate in `detectors/rules.py` is the actual detector — the model
is second-opinion enrichment that degrades to `None` when its version or digest gate fails. See
`models/model_cards/README.md`, which carries a prominent warning that the committed evaluation
artifact is stale and must not be quoted.

The committed training examples are generated lab labels solely to prove the reproducible
train/load/inference path. Before a final accuracy claim, train/validation/test partitions must
be separated by host/session/date for traffic and by DGA family for domains; save class balance,
PR curves, confusion matrices, calibration and model SHA-256 with the resulting model card.
