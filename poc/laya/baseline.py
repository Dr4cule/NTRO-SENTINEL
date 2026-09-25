#!/usr/bin/env python3
"""Conventional non-AI baselines (LogReg, RandomForest) on the SAME test split
Laya sees. These are TRAINED on the labelled train split; Laya is zero-shot.
This is the honest bar Laya must clear to justify ~200ms/predict + 2-3GB RAM.
Runs on system sklearn (no venv needed). See feature_selection.md and §13.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
import common as C
from eval_utils import binary_metrics


def run(feats, train, test):
    Xtr, ytr = train[feats].to_numpy(), train["y"].to_numpy()
    Xte, yte = test[feats].to_numpy(), test["y"].to_numpy()
    models = {
        "logreg": make_pipeline(StandardScaler(),
                                LogisticRegression(max_iter=2000, class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=C.SEED, n_jobs=-1),
    }
    metrics, preds = {}, {}
    for name, m in models.items():
        m.fit(Xtr, ytr)
        yp = m.predict(Xte)
        metrics[name] = binary_metrics(list(yte), list(yp))
        preds[name] = dict(zip(test["event_id"], yp.tolist()))
    return metrics, preds


def main():
    train = pd.read_pickle(os.path.join(C.DATA, "train.pkl"))
    test = pd.read_pickle(os.path.join(C.DATA, "test.pkl"))
    results, allpreds = {}, {}
    for fname, feats in [("compact", C.COMPACT), ("broad", C.BROAD)]:
        results[fname], allpreds[fname] = run(feats, train, test)
    json.dump(results, open(os.path.join(C.DATA, "baseline_results.json"), "w"), indent=2)
    json.dump(allpreds, open(os.path.join(C.DATA, "baseline_preds.json"), "w"), indent=2)
    for fname in results:
        for m, x in results[fname].items():
            print(f"{fname:8} {m:14} acc={x['accuracy']} attack_f1={x['attack_f1']} "
                  f"FPR={x['false_positive_rate']} FNR={x['false_negative_rate']}")


if __name__ == "__main__":
    main()
