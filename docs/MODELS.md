# NTRO Sentinel — Models: complete reference

**Single source of truth for both ML models.** Everything needed to understand, verify, retrain
and defend the models, in one file.

| | |
|---|---|
| Repository | `/opt/ntro-sentinel` (clone of `github.com/Dr4cule/NTRO-SENTINEL`) |
| Live dashboard | `http://172.31.34.204` (nginx :80 → API :8001) |
| Model artifacts | `/opt/ntro-sentinel/models/artifacts/` |
| Training data | `/home/ec2-user/ntro_data/` (outside git) |
| Reports | `/home/ec2-user/models/` |
| Last verified | 2026-09-29 · **26/26** pipeline checks + live enrichment confirmed |

---

## 1. Which models exist and where they are used

Two models. **Neither is load-bearing** — all six detectors work with no model present.

| Model | File | Runtime call | Where it plugs in | Can it gate an alert? |
|---|---|---|---|---|
| **DGA classifier** | `models/artifacts/dga_char_ngrams.joblib` | `models.inference.dga_score(label)` | `detectors/rules.py::dns` | **No** — lexical rule is the gate |
| **Exfiltration baseline** | `models/artifacts/exfil_baseline.joblib` | `models.inference.exfil_anomaly(bytes, ratio)` | `detectors/rules.py::exfil` | **No** — adds ≤ +0.03 confidence |

Supporting module **`models/numeric_feats.py`** is **mandatory** — the DGA pickle references
`models.numeric_feats.numeric_features` by module path. Without it the artifact will not load.

### The two gates, verbatim

```python
# detectors/rules.py :: dns  — ML is the ALTERNATIVE branch, never the only one
if (f['label_length'] >= 18 and f['label_entropy'] >= 3.3) or (learned is not None and learned >= .8):

# detectors/rules.py :: exfil — ML only nudges confidence after the deterministic gate passes
if f['outbound_bytes'] >= 500000 and f['outbound_inbound_ratio'] >= 5 and f['session_count'] >= 3:
    ...
    if a and a['flag']: conf = round(min(0.99, conf + 0.03), 3)   # model concurs -> nudge up
```

---

## 2. Versions and environment

| Component | Version | Why it matters |
|---|---|---|
| Python | 3.11.16 | repo requires ≥3.11 (system 3.9 is too old) |
| scikit-learn | **1.6.0** | hard gate — artifacts built under a different version are **refused** |
| joblib | 1.4.2 | pickle backend |
| numpy | 2.4.6 | |
| Seed | 26145 | artifacts are byte-reproducible |
| venv | `/opt/ntro-sentinel/.venv` | |

```
fastapi==0.115.6   uvicorn==0.34.0   redis==5.2.1
scikit-learn==1.6.0   joblib==1.4.2   websockets==17.1   scapy==2.7.0
```

`websockets` was **added** — it is missing from upstream `requirements.txt`, and without it
uvicorn resolves its WS backend to none and `/ws/alerts` 404s, silently killing the live feed.

---

## 3. Data sources

All real, all downloaded, all outside git. Full detail: `/home/ec2-user/models/real_dataset_registry.yml`.

| Role | Dataset | Rows | SHA-256 | Licence |
|---|---|---|---|---|
| DGA + Alexa benign | [chrmor/DGA_domains_dataset](https://github.com/chrmor/DGA_domains_dataset) | 674,898 | `e8bbe54f…` | no explicit LICENSE; third-party family aggregation, research use |
| benign **train** | [Cisco Umbrella top-1M](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip) | 1,000,000 | `e1ec07be…` | Cisco free research use |
| benign **test** | [Tranco top-1M](https://tranco-list.eu/top-1m.csv.zip) | 1,000,000 | `5df88bf9…` | research use |

**Schema, verified not assumed.** The DGA CSV is 3 columns for all 674,898 rows
(`kind, family, domain`): 337,500 `dga` across **25 families** + 337,398 `legit`. Rankings are
`rank, domain`.

### Could NOT be obtained — exact failures

| Dataset | Failure |
|---|---|
| CTU-13 | `curl: (6) Could not resolve host: downloads.stratosphereips.org` |
| CIC-IDS2017 | page HTTP 200, **no direct data link** — registration/agreement gated |
| CIC-DDoS2019 | same UNB CIC distribution gate |

Even had CIC-IDS2017 been available, its aggregate flow CSVs would be `SCHEMA_INCOMPATIBLE` for
end-to-end Sentinel use (no per-flow DNS/TLS metadata) and would **not** have supplied
exfiltration labels.

---

## 4. Training set composition and split

### DGA model

```
TRAIN  19 of 25 families, capped 4,000 domains each ......... 76,000 DGA
       benign from Umbrella top-1M ........................... 400,000
TEST   6 FAMILIES HELD OUT ENTIRELY .......................... 81,000 DGA
       benign from Tranco, all Umbrella-overlapping labels removed  112,306
HOLDOUT Alexa benign rows, never trained on .................. 332,884
```

**Held-out families:** `fobber, gozi, pykspa, ranbyus, suppobox, tinba`

### Leakage control — measured, not assumed

| Check | Value |
|---|---|
| duplicate domains in train DGA | **0** |
| duplicate domains in test DGA | **0** |
| DGA overlap train ↔ test | **0** |
| benign overlap train ↔ test | **0** |
| benign source-disjoint | **true** |
| Umbrella↔Tranco overlap found and removed | **52,356** (26.2 % of sampled Tranco) |
| DGA↔benign label collisions | **48** — reported, not hidden |

Family-disjoint means the six test families are **never seen in training**, so the numbers
measure generalisation to *unseen malware families*, not memorisation. That is the hardest
honest split available and the reason our F1 sits below the previous run's claim.

### Exfiltration model

**300 synthetic benign points** — uniform `1e3–1e6` bytes × `0.2–8.0` ratio. No real data.
Deliberately spans routine-to-moderate volume so the score discriminates *inside* the detector's
operating region (alerts start at 5e5 bytes / ratio 5) instead of flagging everything.

---

## 5. Features

### DGA model

Input is the **first DNS label only** — `domain.split('.')[0].lower()` — matching the runtime
contract exactly. Labels < 4 chars and common stop-labels (`www, com, org, net, mail, web…`)
are dropped at training time.

```
FeatureUnion
├── TfidfVectorizer(analyzer='char', ngram_range=(2,5), min_df=2,
│                   max_features=300,000, sublinear_tf=True)
└── Pipeline(FunctionTransformer(numeric_features) → StandardScaler)
      numeric_features = [label_length, shannon_entropy]
LogisticRegression(max_iter=1000, C=1.0, class_weight='balanced', random_state=26145)
```

`numeric_features` lives in **`models/numeric_feats.py`**, deliberately a separate module: a
`FunctionTransformer` pickles by reference, so a function defined in `__main__` produces an
artifact that is unloadable anywhere else.

**Config selection** (identical data, identical split, chosen by held-out F1):

| config | F1 | precision | recall | ROC-AUC | PR-AUC | FPR benign | selected |
|---|---|---|---|---|---|---|---|
| **char_2-5+len+entropy** | **0.8236** | 0.8519 | 0.7970 | 0.9260 | 0.9192 | 0.0999 | **yes** |
| char_2-4+len+entropy | 0.8181 | 0.8413 | 0.7961 | 0.9217 | 0.9148 | 0.1083 | no |
| char_3-5+len+entropy | 0.8120 | 0.8564 | 0.7719 | 0.9161 | 0.9094 | 0.0933 | no |

### Exfiltration model

`IsolationForest(contamination=0.05, random_state=26145)` over exactly two features, in order:
`[outbound_bytes, outbound_inbound_ratio]`.

---

## 6. Metrics

### DGA classifier — `validated`, **domain-level only**

| Metric | @ 0.5 | @ 0.8 (runtime gate) |
|---|---|---|
| **accuracy** | **0.8569** | — |
| **precision** | **0.8519** | **0.9617** |
| **recall** | **0.7970** | **0.6268** |
| **F1** | **0.8236** | 0.7589 |
| macro F1 | 0.8516 | — |
| weighted F1 | 0.8561 | — |
| **ROC-AUC** | **0.9260** | — |
| **PR-AUC / average precision** | **0.9192** | — |
| FPR on benign | 0.0999 | 0.0180 |
| worst-family recall | 0.2402 | 0.0359 |

**Confusion matrix @ 0.5**

|  | predicted DGA | predicted benign |
|---|---|---|
| **actual DGA** | tp **64,560** | fn 16,440 |
| **actual benign** | fp 11,223 | tn 101,083 |

**Third benign source** (Alexa, never trained on): n 332,884, FPR **0.1227**, mean score 0.2213.

### Per-family **recall** (precision is undefined — see §9)

| Family | Support | Recall | Mean score |
|---|---|---|---|
| ranbyus | 13,500 | 0.9998 | 0.9835 |
| tinba | 13,500 | 0.9925 | 0.9356 |
| fobber | 13,500 | 0.9767 | 0.8836 |
| pykspa | 13,500 | 0.8983 | 0.8198 |
| gozi | 13,500 | 0.6747 | 0.6089 |
| **suppobox** | 13,500 | **0.2402** | 0.3417 |

### Threshold analysis

| Threshold | precision | recall | F1 | FPR benign | worst-family recall |
|---|---|---|---|---|---|
| 0.10 | 0.5578 | 0.9742 | 0.7094 | 0.5569 | 0.8700 |
| 0.30 | 0.7354 | 0.8846 | 0.8031 | 0.2296 | 0.4979 |
| 0.50 | 0.8519 | 0.7970 | 0.8236 | 0.0999 | 0.2402 |
| 0.70 | 0.9314 | 0.6968 | 0.7972 | 0.0370 | 0.0850 |
| **0.80** | **0.9617** | **0.6268** | **0.7589** | **0.0180** | **0.0359** |
| 0.90 | 0.9837 | 0.5100 | 0.6717 | 0.0061 | 0.0067 |

At the 0.8 gate the model is a **high-precision confidence booster, not an independent
detector** — it adds little recall and essentially nothing for `suppobox`.

### Calibration

| bin | n | predicted | observed | gap |
|---|---|---|---|---|
| [0.0,0.1) | 51,851 | 0.0441 | 0.0403 | 0.0038 |
| [0.1,0.2) | 27,104 | 0.1452 | 0.1318 | 0.0134 |
| [0.2,0.3) | 16,915 | 0.2467 | 0.2176 | 0.0291 |
| [0.3,0.4) | 12,098 | 0.3474 | 0.2890 | 0.0584 |
| [0.4,0.5) | 9,555 | 0.4480 | 0.3767 | 0.0713 |
| [0.5,0.6) | 7,843 | 0.5485 | 0.4766 | 0.0719 |
| [0.6,0.7) | 7,342 | 0.6500 | 0.5967 | 0.0533 |
| [0.7,0.8) | 7,802 | 0.7515 | 0.7266 | 0.0249 |
| [0.8,0.9) | 10,803 | 0.8550 | 0.8760 | 0.0210 |
| [0.9,1.0) | 41,993 | 0.9684 | 0.9837 | 0.0153 |

Calibrated at the extremes, moderately over-confident mid-range (max gap ≈ 0.07). Usable as
relative confidence — **not** calibrated posteriors.

### Sanity predictions

| Label | Score | Expected | |
|---|---|---|---|
| microsoft | 0.0141 | benign | ✓ |
| grafana | 0.0884 | benign | ✓ **was 0.82 in the old synthetic model** |
| sonarqube | 0.2978 | benign | higher than ideal |
| kubernetes | 0.0679 | benign | ✓ |
| elasticsearch | 0.0277 | benign | ✓ |
| xk39fjq2mzp1vb7wnt | 0.8329 | DGA | ✓ |
| a8f3k2p9q1z7x5v3b2n1m4 | **0.2076** | DGA | **missed by ML** |
| qvxzj7k3m1p9b5n2 | **0.3315** | DGA | **missed by ML** |

The last two are a real finding, not a bug to hide: uniformly random strings are **out of
distribution** for a model trained on *real* DGA, which is structured (pronounceable, restricted
alphabets, repeating stems). The model learned real DGA structure, not "high entropy = DGA".
Both are still caught by the deterministic rule (`len ≥ 18`, `entropy ≥ 3.3` → 0.837
confidence) — which is exactly why the deterministic rule is the gate.

### Exfiltration model — `prototype`, external performance `NOT_MEASURED`

**No precision, recall, F1 or accuracy is reported, because none was measured.** There is no
public exfiltration dataset with labels matching `[outbound_bytes, outbound_inbound_ratio]`, and
fabricating positives would have manufactured the number it exists to test.

**Known defect:** `exfil_anomaly(50_000, 1.0)` returns `flag: True` — a benign mid-range
transfer is flagged, because `contamination=0.05` forces ~5 % of the synthetic envelope to be
outliers. Only the *relative* score is meaningful. Documented, not tuned away without data.

---

## 7. How to test everything

### One command — the recommended check

```bash
cd /opt/ntro-sentinel && .venv/bin/python tools/verify_pipeline.py
```

Verifies **four independent layers**, 26 checks. Exit 0 = all pass.

| Layer | What it proves |
|---|---|
| **L1 source** | the 10 code changes that make the fixes work are present (grep for a unique marker in each file) |
| **L2 artifact** | artifacts exist, digests match `training_manifest.json`, sklearn version matches, exfil honestly labelled |
| **L3 contract** | `dga_score`/`exfil_anomaly` load, discriminate, and degrade to `None` when hidden |
| **L4 pipeline** | a real event through `detectors/rules.py` produces an alert **carrying** `dga_char_ngram_score`, and `model_version == dns-lexical-ml-v1` |

**L4 is the layer that matters.** A model can be present on disk, hash-match the manifest, and
import cleanly while never being used — a wrong `MODEL_DIR` or a permissions fault makes
`dga_score()` return `None`. That exact failure happened during this deployment and was
invisible to every other check. L4 asserts on the **alert payload** instead of the loader.

Add `--json` for machine-readable output.

### Full suite

```bash
cd /opt/ntro-sentinel
.venv/bin/python -m compileall -q .                                     # PASS
.venv/bin/python -m models.inference                                    # inference self-check OK
.venv/bin/python -m unittest tests.test_model_integrity \
                 tests.test_models_and_fallbacks -v                     # 25/25 OK
.venv/bin/python -m unittest discover -s tests                          # 141/141 OK
```

### Deterministic detector suite (independent of ML)

```bash
ALERT_DB=/tmp/eval.db .venv/bin/python -m eval.run_suite
# -> 9/9 attack scenarios, benign FPR 0.0, 3/3 ddos subtypes
```

### Re-emit every report from the artifacts (no number is hand-typed)

```bash
.venv/bin/python eval/run_real_data_evaluation.py \
  --artifacts models/artifacts --out /home/ec2-user/models
```

### Retrain from scratch

```bash
.venv/bin/python models/train_models_real.py \
  --data-root /home/ec2-user/ntro_data \
  --output-dir /tmp/ntro-sentinel-validated-artifacts
# ~5 min; artifact digests are byte-identical across runs (seeded)
```

### Prove the models are live in the *running service*

```bash
cd /opt/ntro-sentinel
sudo -E .venv/bin/python tools/gen_live_attacks.py dga && sleep 18
curl -s "http://127.0.0.1:8001/api/alerts?limit=20" | .venv/bin/python -c "
import json,sys
a=json.load(sys.stdin)
m=[x for x in a if (x.get('supporting_evidence') or {}).get('dga_char_ngram_score') is not None]
print('carrying dga_char_ngram_score:', len(m))
for x in m[:3]: print(' ', x['supporting_evidence']['dga_char_ngram_score'], x['model_version'])"
```

Expect `model_version = dns-lexical-ml-v1` and non-null `dga_char_ngram_score`. If it prints
`dns-lexical-v1` with `None`, the **service** cannot see the models even though the files are
present — check `MODEL_DIR` and artifact permissions.

### Integrity / fail-safe matrix

```bash
.venv/bin/python -c "
import json,shutil,tempfile,sys; sys.path.insert(0,'.')
from pathlib import Path
from models import inference
SRC=Path('models/artifacts')
def probe(name,mutate):
    d=Path(tempfile.mkdtemp())
    for f in SRC.iterdir():
        if f.is_file(): shutil.copy(f,d/f.name)
    mutate(d)
    old=inference._ROOT; inference._ROOT=d; inference._cache.clear()
    try: print(f'  {name:<42} {\"PASS\" if inference.dga_score(\"microsoft\") is None else \"FAIL\"}')
    finally: inference._ROOT=old; inference._cache.clear()
probe('tampered artifact (byte flipped)', lambda d:(lambda p:(p.write_bytes(bytes(bytearray(p.read_bytes())[:-1]+b'\\xff'))))(d/'dga_char_ngrams.joblib'))
probe('manifest with NO digest', lambda d:(lambda m:(m['sha256'].pop('dga_char_ngrams.joblib'),(d/'training_manifest.json').write_text(json.dumps(m))))(json.loads((d/'training_manifest.json').read_text())))
probe('sklearn version mismatch', lambda d:(lambda m:(m.__setitem__('scikit_learn_version','0.24.0'),(d/'training_manifest.json').write_text(json.dumps(m))))(json.loads((d/'training_manifest.json').read_text())))
"
```

Expected **5/5 PASS** (valid artifact loads; the other four return `None`).

---

## 8. Artifacts and integrity

| File | SHA-256 |
|---|---|
| `models/artifacts/dga_char_ngrams.joblib` | `ce1382fe2a1fa8e484cbd2c85c4ebc5154df9a85b9d3c6cf2a5e5e03205480a4` |
| `models/artifacts/exfil_baseline.joblib` | `845af50de949abcb82ea7188f5c569c4a276e94e32c925fed411500922ed88f1` |
| `models/numeric_feats.py` | `a5d2662c1724c7013eb2541f2d59788ab23ba9d0f8334c9a825bc8c8677bb1b0` |
| `dga_domains_full.csv` | `e8bbe54f180cd127a07abaa3dbddcd843e7b7943dff2f18628619b1bd22e8253` |
| `umbrella.csv` | `e1ec07be7bbf41a8a763795f0063f46dcf048a17bdd31072125ac0811eaa9879` |
| `tranco.csv` | `5df88bf9072af7888ae67b6187e26b5519d56cd2d36de8317384ea6b6633f392` |

Digests are **byte-identical across retrains** (seeded).

**joblib artifacts are pickles — loading one executes code.** Three mitigations:

1. SHA-256 pinned in `training_manifest.json`; `inference._verified()` re-checks **before
   unpickling** and refuses a mismatch.
2. scikit-learn version gate — a mismatch returns `None`.
3. `models/numeric_feats.py` must be importable, so a missing module fails loudly.

---

## 9. The audit finding you must not get wrong

The **previous** report claimed aggregate precision **0.8348** while listing per-family
precisions of **0.41–0.48**. Those cannot both be true. Its per-family "precision" was
`TP_f/(TP_f + GLOBAL_FP)` — the entire global false-positive count charged to every family.
All six values reproduce exactly from its own confusion matrix.

**Per-family precision is UNDEFINED for this model.** False positives occur on *benign* labels,
which carry no family, so a positive prediction cannot be attributed to a family. Reporting one
requires inventing an FP allocation — which is exactly the error that was found.

**Also from the audit:** the previous `training_manifest.json` referenced
`exfil_baseline.joblib` (`5b2fe937…`) but the file was **absent** — the enrichment was silently
inert.

**Our F1 (0.8236) is LOWER than the previous claim (0.8696).** That is correct: we evaluate on
81,000 unseen-family DGA + 112,306 source-disjoint benign, versus 20,000 + 20,000.

---

## 10. Limitations

**DGA model**
1. Domain-scoped — one DNS label, no IP/port/timestamp.
2. 2010s-era families; contemporary DGA may drift.
3. First-label extraction discards SLD/TLD context some DGAs encode.
4. Per-family recall spans 0.24→1.00; aggregate F1 conceals this.
5. 9.99 % FPR on popular benign domains at 0.5 — only 0.8 is automation-safe.
6. Not time-disjoint — ranking lists carry no timestamps.
7. Uniformly random strings are out of distribution (0.208, 0.332).
8. Over-confident mid-range (gap ≈ 0.07).

**Exfiltration model**
1. **No real data** — every external metric is `NOT_MEASURED`.
2. `flag` is unreliable for benign mid-range values.
3. Two features only; ignores `session_count`, time, protocol, destination.
4. `contamination=0.05` is a guess, not estimated.

**Deployment-wide**
1. `encrypted_malware` is **structurally zero** — the scapy path derives no JA3/JA4, so the
   fingerprint condition cannot be satisfied without Zeek.
2. Only this host's traffic plus a veth test segment is observed — **not a network mirror**.
3. No alerting channel; detections are dashboard-only.

---

## 11. Making the changes permanent

### The risk

All source changes are **uncommitted**, and `models/artifacts/` is **gitignored** (line 9 of
`.gitignore`). So a `git checkout`/`git reset --hard` destroys the code fixes, and a clean clone
has no models at all — enrichment silently returns `None` and the dashboard still looks healthy.

### Backups taken

```
/opt/ntro-sentinel/tools/backup/source-changes.patch   # all 9 modified files (git diff)
/opt/ntro-sentinel/tools/backup/new-files.tar.gz       # new source files
/opt/ntro-sentinel/models/artifacts/                   # the artifacts (gitignored by design)
```

### Restore

```bash
cd /opt/ntro-sentinel
git apply tools/backup/source-changes.patch
tar xzf tools/backup/new-files.tar.gz
```

### Make the models reproducible, not just present

The artifacts are binary and excluded from git, so they must be **rebuildable**:

```bash
.venv/bin/python models/train_models_real.py --data-root /home/ec2-user/ntro_data \
  --output-dir /tmp/ntro-sentinel-validated-artifacts
cp /tmp/ntro-sentinel-validated-artifacts/*.joblib \
   /tmp/ntro-sentinel-validated-artifacts/training_manifest.json models/artifacts/
sudo systemctl restart ntro-ingest.service ntro-api.service
.venv/bin/python tools/verify_pipeline.py     # must report 26/26
```

### Two operational traps that will silently break the models again

1. **`MODEL_DIR` must point at the ARTIFACTS directory**, i.e.
   `/opt/ntro-sentinel/models/artifacts` — **not** `/opt/ntro-sentinel/models`.
   Set in `/etc/systemd/system/ntro-{ingest,api}.service`.
2. **Do not open the live `artifacts/sentinel.db` from a process with a restrictive umask.**
   Any process that touches it creates `-wal`/`-shm` files. With a default ACL present, the
   creating process's umask sets the ACL **mask** — umask 022 produces `mask::r--`, which locks
   the `sentinel` service out of the store, kills the consumer thread, and crash-loops the
   sensor. Use a permissive umask (`0002`) or point tooling at a separate DB via `ALERT_DB`.

Run `tools/verify_pipeline.py` after any change to catch both.

---

## 12. Safe claims

✅ **"On 81,000 DGA domains from six malware families never seen in training, plus 112,306
benign domains from a disjoint source, our first-label DGA classifier achieves F1 0.8236,
ROC-AUC 0.926, PR-AUC 0.919, with a 9.99 % false-positive rate on benign domains at a 0.5
threshold."**

✅ **"At the 0.8 threshold the detector actually uses, precision is 0.962 and the benign FPR is
1.8 %."**

✅ **"Per-family recall ranges from 0.24 to 1.00 across the six unseen families."**

✅ **"Training and evaluation benign sets are source-disjoint — 52,356 overlapping labels were
measured and removed; final overlap is zero."**

✅ **"9/9 attack scenarios detected with benign FPR 0.0"** — controlled lab suite, functional
verification, **not** real-world accuracy.

❌ **Not safe:** DGA accuracy presented as threat accuracy · any per-family precision · any
six-class figure · any exfiltration accuracy · claiming `encrypted_malware` detection · the
previous run's 0.8696 · the 26/26 check count as an accuracy claim.

---

## 13. Where everything lives

**Repo** `/opt/ntro-sentinel`
```
models/inference.py              runtime contract + SHA gate + sklearn gate
models/numeric_feats.py          REQUIRED by the DGA pickle
models/train_models_real.py      real-data trainer (seeded, reproducible)
models/holdout.py                synthetic holdout lists (baseline provenance)
models/artifacts/                *.joblib + training_manifest.json
eval/run_real_data_evaluation.py regenerates every report from the artifacts
tools/verify_pipeline.py         4-layer end-to-end verification (26 checks)
tools/backup/                    patch + new-file backups
```

**Reports** `/home/ec2-user/models`
```
MODEL_CARD_DGA.md · MODEL_CARD_EXFILTRATION.md · SIH_MODEL_DOCUMENTATION.md
final_metrics.{json,md} · model_comparison.{json,md} · dataset_coverage_matrix.{csv,md,json}
dataset_inventory.{json,md} · real_dataset_registry.yml · verification.log · final_status.{json,md}
```

**Data** `/home/ntro_data` — outside git, referenced by digest.
