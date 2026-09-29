#!/usr/bin/env python3
"""Metrics shared by the baseline and the Laya analysis. `attack` is positive."""
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score

LABELS = ["benign", "attack"]

def binary_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=LABELS)
    (tn, fp), (fn, tp) = cm
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    return {
        "n": len(y_true),
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "benign_precision": round(float(p[0]), 4), "benign_recall": round(float(r[0]), 4),
        "benign_f1": round(float(f1[0]), 4),
        "attack_precision": round(float(p[1]), 4), "attack_recall": round(float(r[1]), 4),
        "attack_f1": round(float(f1[1]), 4),
        "macro_f1": round(float((f1[0] + f1[1]) / 2), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else None,
        "confusion": {"tn_benign_ok": int(tn), "fp_benign_as_attack": int(fp),
                      "fn_attack_as_benign": int(fn), "tp_attack_ok": int(tp)},
    }
