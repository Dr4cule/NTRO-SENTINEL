# Model cards

## Known limitation — the committed `dga_holdout_evaluation.json` is STALE and overstates the score

The committed artifact reports **precision 1.0 / recall 1.0 / F1 1.0**. That number is **not
trustworthy** and must not be quoted.

It was produced before the F-06 fix, when `train_models.py` and `evaluate_models.py` both drew
their benign labels from the same eight words. The model was therefore scored on the exact
vocabulary it had memorised — a self-test, not a measurement.

Re-running `make model-eval` on the **disjoint** holdout (`models/holdout.py`, F-06 fix) gives:

| | leaked split (old, invalid) | disjoint holdout (current) |
|---|---|---|
| precision | 1.00 | **0.32** |
| recall | 1.00 | **1.00** |
| F1 | 1.00 | **0.48** |

255 of 270 held-out benign labels are predicted DGA. Diagnosis: the model learned **token
length, not entropy** — `grafana` (7 chars) scores 0.82, `sonarqube` (9) 0.84, while the
memorised training words score ~0.12.

The committed `dga_holdout_evaluation.json` still shows the old figure only because
`models/artifacts/` is root-owned (written by the `trainer` Docker profile, which runs as
uid 0 specifically to write the bind mount) and cannot be overwritten without `sudo`. Regenerate
with `sudo chown $(id -u):$(id -g) models/artifacts/*` then `make model-eval`.

This is left visible deliberately. The lexical gate in `detectors/rules.py` is the actual DGA
detector; the ML is second-opinion enrichment that degrades to `None` when the artifact fails
its version or digest gate. A low honest number here is more useful than a high fake one, and
fixing it properly needs real labelled DGA families with per-family splits.

## `dga_char_ngrams.joblib`

Character TF-IDF (2–5 grams) plus Logistic Regression. The reproducible training command is `make train`; `make model-eval` writes `dga_holdout_evaluation.json` beside the artifact. Its training data is generated, labelled lab strings, so it demonstrates the train/inference/evaluation path only. It must not be described as a real-world DGA accuracy result — and note the disjoint-holdout score above is 0.48 F1, not 1.0. Before submission to a production setting, retrain/evaluate on a documented, family-separated public/lab source and include its group split, class balance, PR curve, calibration and result artifact. The artifact is SHA-256 pinned in `training_manifest.json` and refused at load if the digest or scikit-learn version does not match.

## `exfil_baseline.joblib`

Isolation Forest baseline over outbound bytes and byte ratio, trained on generated benign-like feature points. The deployed deterministic exfil rule remains the fast path; this model is packaged for the online-baseline extension and has no public-dataset metric claim. It is enrichment only — it can raise an exfil alert's confidence but is never the gate.
