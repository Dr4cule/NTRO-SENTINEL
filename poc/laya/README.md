# Laya POC — is a local structured-decision model useful for SentinelFlow?

**Isolated, measurement-only.** Nothing here imports from or modifies the
production SentinelFlow pipeline. It reads one labelled CSV read-only and writes
only inside `poc/laya/`. No fine-tuning, no integration — this exists to answer
one question with evidence: *does Laya earn a place in the pipeline?*

The honest bar: Laya (zero-shot) is compared against conventional models
(LogisticRegression, RandomForest) **trained** on the same features, scored on
the **same** held-out flows. If a 3 GB, ~1 s/flow model can't beat or usefully
complement a RandomForest that trains in seconds, that is the finding.

## Data
CIC-IDS2017 `Friday-WorkingHours-Afternoon-DDos` — BENIGN vs DDoS flows.
Only 2 classes here, so the multi-class question is limited to this binary.
Features are **bidirectional** (the CSV's nature) while SentinelFlow is one-way —
see the caveat in `feature_selection.md`.

## Anti-cheating
The model never sees the `Label`, `Destination Port` (a near-label leak in this
capture), IPs, ports, or timestamps. Included/excluded columns are documented in
`feature_selection.md`.

## Run order
```bash
python3 poc/laya/inspect_dataset.py     # -> dataset_report.json (system python)
python3 poc/laya/make_sample.py         # -> data/{train,test}.pkl  (deterministic, SEED=42)
python3 poc/laya/baseline.py            # -> data/baseline_*.json   (trained bar)
poc/laya/.venv/bin/python poc/laya/smoke_laya.py   # 1 flow: load time, RAM, latency, raw schema
poc/laya/.venv/bin/python poc/laya/run_laya.py     # full test split -> data/laya_preds_*.json + laya_runtime.json
python3 poc/laya/analyze.py             # -> laya_vs_baseline.csv, laya_disagreements.csv, analysis.json
```
Laya runs in-process on CPU (`device="cpu"`); the `laya-serve` HTTP server is
never used (it binds 0.0.0.0 without auth unless `LAYA_API_KEY` is set).

## Files
- `common.py` — CSV load/clean, feature sets (COMPACT/BROAD), label-free state builder.
- `eval_utils.py` — shared binary metrics (attack = positive).
- `smoke_laya.py` / `run_laya.py` — Laya inference + latency/RAM measurement.
- `baseline.py` — trained LogReg + RandomForest on the same split.
- `analyze.py` — metrics table, ECE calibration, head-coherence, FP-adjudication, disagreements.
- `results.md` — the evidence-backed verdict (written from the measured numbers).
- `data/` — split pickles + all prediction/metric artifacts (gitignored-size, reproducible).

## Verdict
See `results.md`. Written strictly from measured numbers — a negative result is
reported as-is.
