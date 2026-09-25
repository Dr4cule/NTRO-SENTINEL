# Laya on SentinelFlow — GPU test & decision runbook (Windows)

**You are here because:** the Laya evaluation POC is built and validated on CPU,
but CPU inference is ~1.3 s/flow. Rerun it on your NVIDIA GPU (much faster),
read the numbers, and decide with evidence whether Laya earns a place in
SentinelFlow. **Nothing here has touched the production pipeline, and nothing
should until the numbers justify it.**

Clone this branch, `cd poc/laya`, and follow the steps below top to bottom.

---

## 0. What is already known (measured on CPU — your baseline to beat/compare)

- **Trained baselines are near-perfect on this task.** On a 1000-flow held-out
  split (500 benign / 500 DDoS), same features fed to everyone:
  - RandomForest (broad): **acc 0.999, attack-F1 0.999, FPR 0.000, FNR 0.002**
  - RandomForest (compact): acc 0.998, FPR 0.000
  - LogReg (broad): acc 0.988, FPR 0.024 · LogReg (compact): acc 0.953, FPR 0.092
  This is the honest bar. A zero-shot 3 GB model has to justify itself against
  a RandomForest that trains in seconds and runs in microseconds.
- **Laya is heavy.** `convaiinnovations/laya-typed-decisions` (ModernBERT-large,
  421M): **~3.2 GB RSS**, cold load ~81 s (first download), ~5 s cached.
  CPU inference **~1.3 s/flow** (this is what your GPU should crush).
- **Laya looked incoherent on the one flow tested (n=1, not conclusive):** on a
  true attack flow, `traffic_class`→"attack" (prob 0.60, barely over chance)
  while the `is_malicious` noul head said 0.20 (i.e. "benign"). The two heads
  contradicted each other, and the model logged an "uncalibrated temperatures"
  warning at load. Your full GPU run confirms or refutes whether this holds.

**The point of the POC is to discover if Laya is useful — a negative result is a
valid, publishable result. Do not tune prompts to flatter it.**

---

## 1. Rules (non-negotiable)

- **Do NOT modify the production pipeline** to run this test: not
  `engine/stream_consumer.py`, detectors, correlation, alert/hash-chain, or the
  dashboard. Everything lives under `poc/laya/`.
- **Anti-cheating:** the model is never given the label, `Destination Port` (a
  near-label leak in this capture — the only attack is an HTTP flood to :80),
  IPs, ports, or timestamps. See `feature_selection.md`. Keep it that way.
- **Never run `laya-serve`.** It binds `0.0.0.0` with no auth unless
  `LAYA_API_KEY` is set. This POC loads the model **in-process** only.
- **Do NOT fine-tune and do NOT integrate** until the measured verdict says so.

## 2. Prerequisites

- Windows with an **NVIDIA GPU** + recent driver (check `nvidia-smi`).
- **Python 3.11+** (3.13 is fine).
- The dataset CSV: `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  (CIC-IDS2017). ~77 MB. Put it anywhere; you'll point `CIC_CSV` at it.

## 3. Setup (PowerShell, from repo root after cloning the `testing` branch)

```powershell
cd poc\laya
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install laya pandas scikit-learn
```

`laya` pulls in `torch` (CUDA build) + `transformers`. Verify the GPU is seen:

```powershell
python -c "import torch; print('cuda', torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else '-')"
```

Point the scripts at your CSV (this shell session only):

```powershell
$env:CIC_CSV = "C:\path\to\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
```

Device is auto-detected (CUDA if available). To force it: `$env:LAYA_DEVICE="cuda"`.
If the first model load hangs, set `$env:USE_TF="0"`.

## 4. Run order (each step writes into `poc\laya\data\`)

```powershell
python inspect_dataset.py     # -> dataset_report.json         (sanity: 225,745 rows, 2 classes)
python make_sample.py         # -> data\{train,test}.pkl        (deterministic, SEED=42)
python baseline.py            # -> data\baseline_*.json         (the trained bar)
python smoke_laya.py          # 1 flow: load time, VRAM/RAM, latency, raw output schema
python run_laya.py            # full 1000-flow split, both feature sets -> data\laya_preds_*.json, laya_runtime.json
python analyze.py             # -> laya_vs_baseline.csv, laya_disagreements.csv, analysis.json
```

`run_laya.py` is the long one. On CPU it was ~1.3 s/flow (≈40 min for 2000
predictions). On GPU expect **~30–100 ms/flow** → a few minutes. If you want a
faster first pass, shrink the split: `python make_sample.py 200 2000`
(200/class test, 2000/class train) then rerun `baseline.py` and `run_laya.py`.

## 5. The questions to answer (with where the number comes from)

`analyze.py` already computes all of these into `analysis.json` +
`laya_vs_baseline.csv` + `laya_disagreements.csv`. Read them and fill in §7.

1. **Q1 — Accuracy vs baseline.** Does zero-shot Laya's `traffic_class` beat, tie,
   or lose to LogReg/RandomForest? → `laya_vs_baseline.csv` (accuracy, attack_f1,
   FPR, FNR per model per feature set).
2. **Q2 — Multi-class.** This CSV is only BENIGN vs DDoS, so multi-class is out of
   scope here. Note it as a limitation; a fuller test needs a multi-attack CSV
   (e.g. other CIC-IDS2017 days: PortScan, Bot, Infiltration).
3. **Q3 — Compact vs broad features.** Does more context help or hurt Laya's
   zero-shot reasoning? Compare the two `laya_zero_shot` rows.
4. **Q4 — FP-adjudication (the most relevant use case).** Can Laya veto an
   over-eager detector's false alarms WITHOUT suppressing real attacks?
   → `analysis.json → fp_adjudication`: `rescue_rate` (FPs correctly killed —
   higher is better) vs `damage_rate` (real attacks wrongly vetoed — MUST be near
   0, this is the dangerous number).
5. **Q5 — Latency & memory / throughput.** → `laya_runtime.json`: single-call
   p50/p95/p99, batched throughput (flows/s), peak RSS (and note VRAM from
   `nvidia-smi` during the run). Compare to the pipeline's ~2.6 ms/event.
   Remember production would run Laya **candidate-only** (~8% of events), not on
   every flow.

**Also measured for you:**
- **Calibration** — `analysis.json → *_coherence → p_attack_ece` (Expected
  Calibration Error). The model card claims ECE ~0.21 (over-confident). >0.1
  means you cannot trust the probability as a score without recalibration.
- **Head coherence** — `choice_vs_noul_contradiction_rate`: how often the two
  heads disagree on the same flow. High = the model isn't reasoning coherently
  about netflow (the n=1 CPU finding, checked at scale).
- **Disagreements** — `laya_disagreements.csv`: every flow Laya got wrong, with
  both baselines' calls, for eyeballing failure modes.

## 6. Reproducibility & optional deeper tests

- **Double-run check:** run `run_laya.py` twice; predictions should be identical
  (SEED=42 split, deterministic model). If they drift, note it.
- **Optional — real SentinelFlow evidence:** the strongest test is running Laya
  on the actual structured evidence SentinelFlow stores (from `alertstore`),
  not just CIC rows. If you want this, build states from stored alerts'
  `supporting_evidence` dicts and feed them through the SAME question schema in
  `smoke_laya.py`. This measures Laya on the real in-domain inputs it would see
  as an adjudicator. (Still read-only; still no production changes.)

## 7. Write the verdict into `results.md`

Fill `poc/laya/results.md` (new file) strictly from the measured numbers. Pick
ONE headline verdict and defend it with the CSV/JSON figures:

| Verdict | Choose when |
|---|---|
| **DO NOT USE** | Laya loses badly to the baseline AND `damage_rate` > ~0.02 (it would suppress real attacks). Most likely outcome given the CPU preview. |
| **KEEP EXPERIMENTAL** | Interesting but not trustworthy: near-baseline accuracy but poor ECE / high contradiction rate. Revisit after fine-tuning. |
| **ADJUDICATOR ONLY** | Laya doesn't classify well alone, but on Q4 it kills false positives (`rescue_rate` high) with `damage_rate` ≈ 0. Then it's a *second-opinion veto on candidate alerts only*, never a primary detector. |
| **INTEGRATE** | Laya matches/beats the baseline AND is calibrated AND `damage_rate` ≈ 0 AND latency is acceptable candidate-only. Unlikely for zero-shot; would need the numbers to really show it. |

Decision rule: **a model that ever vetoes a real attack (`damage_rate` > 0) can
never sit in the alert path as a suppressor.** That single number gates the
ADJUDICATOR/INTEGRATE verdicts.

## 8. IF (and only if) the verdict is favorable — the integration slot

Do not write this until measured. When justified, the low-risk slot is in
`engine/stream_consumer.py`, `Pipeline.process()`, **after** a detector produces
a candidate alert and **before** `store.append()`:

- Enrich `alert['ai_assessment']` = Laya's `{choice, p_attack, noul, confidence}`.
  It lands in the hash-chained record = provenance, no new trust surface.
- **Candidates only** (~8% of events) — never every flow. Keeps latency sane.
- **Graceful degrade:** wrap in try/except + timeout; on any failure set
  `ai_assessment = {"status": "unavailable"}` and let the deterministic alert
  through unchanged. Mirror the None-degradation pattern in `models/inference.py`.
- **Advisory only** unless ADJUDICATOR is justified: it annotates, it does not
  suppress. Suppression requires `damage_rate` ≈ 0 proven at scale.

## 9. Troubleshooting

- Model load hangs → `$env:USE_TF="0"`.
- OOM on GPU → the model is ~1.6 GB weights; needs a few GB VRAM. Close other
  GPU apps, or run on CPU (`$env:LAYA_DEVICE="cpu"`).
- `CIC_CSV` not found → check the path; `inspect_dataset.py` reads it first.
- Slow first run → weights download (~1.6 GB) is one-time; cached after.

---

**Bottom line:** the baseline is already at 99.9%. Laya's realistic hope is the
**ADJUDICATOR** role (Q4), not primary detection. Let the GPU numbers — accuracy,
`damage_rate`, ECE, contradiction rate — make the call. Report honestly.


