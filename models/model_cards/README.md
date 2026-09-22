# Model cards

## `dga_char_ngrams.joblib`

Character TF-IDF (2–5 grams) plus Logistic Regression. The reproducible training command is `make train`; `make model-eval` writes `dga_holdout_evaluation.json` beside the artifact. Its starter data is generated, labelled lab strings (benign-like labels and random DGA-like labels), so it demonstrates the train/inference/evaluation path only. It must not be described as a real-world DGA accuracy result. Before submission to a production setting, retrain/evaluate on a documented, family-separated public/lab source and include its group split, class balance, PR curve, calibration and result artifact.

## `exfil_baseline.joblib`

Isolation Forest baseline over outbound bytes and byte ratio, trained on generated benign-like feature points. The deployed deterministic exfil rule remains the fast path; this model is packaged for the online-baseline extension and has no public-dataset metric claim.
