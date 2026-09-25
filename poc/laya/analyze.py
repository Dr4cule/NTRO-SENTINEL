#!/usr/bin/env python3
"""Turn the raw Laya + baseline predictions into the POC's evidence:
comparison table, calibration (ECE), head coherence, disagreements, and the
FP-adjudication test. Pure python + sklearn; does NOT load Laya.
Run after run_laya.py finishes.
"""
import os, sys, json, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import common as C
from eval_utils import binary_metrics

D = C.DATA


def load(name):
    return json.load(open(os.path.join(D, name)))


def ece(pairs, bins=10):
    """Expected Calibration Error of p_attack vs actual attack outcome."""
    if not pairs:
        return None
    buckets = [[] for _ in range(bins)]
    for p, y in pairs:
        buckets[min(bins - 1, int(p * bins))].append((p, y))
    tot, e = len(pairs), 0.0
    for grp in buckets:
        if not grp:
            continue
        conf = sum(p for p, _ in grp) / len(grp)
        acc = sum(1 for _, y in grp if y) / len(grp)
        e += (len(grp) / tot) * abs(conf - acc)
    return round(e, 4)


def main():
    test = pd.read_pickle(os.path.join(D, "test.pkl"))
    truth = dict(zip(test["event_id"], test["y"]))
    base, base_preds = load("baseline_results.json"), load("baseline_preds.json")
    runtime = load("laya_runtime.json")
    analysis = {"runtime": runtime, "laya_metrics": {}}

    # --- comparison table: Laya vs trained baselines, both feature sets ---
    rows = []
    for fs in ("compact", "broad"):
        lp = load(f"laya_preds_{fs}.json")
        ev = list(lp.keys())
        m = binary_metrics([truth[e] for e in ev], [lp[e]["choice"] for e in ev])
        analysis["laya_metrics"][fs] = m
        rows.append(("laya_zero_shot", fs, m))
        for mdl in ("logreg", "random_forest"):
            rows.append((mdl, fs, base[fs][mdl]))
    with open(os.path.join(D, "laya_vs_baseline.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["model", "featureset", "n", "accuracy", "attack_f1", "benign_f1", "FPR", "FNR"])
        for mdl, fs, m in rows:
            w.writerow([mdl, fs, m["n"], m["accuracy"], m["attack_f1"], m["benign_f1"],
                        m["false_positive_rate"], m["false_negative_rate"]])

    # --- coherence (do the two heads agree?) + calibration + noul-as-classifier ---
    for fs in ("compact", "broad"):
        lp = load(f"laya_preds_{fs}.json")
        ev = list(lp.keys())
        contra = sum((lp[e]["choice"] == "attack") != (lp[e]["noul"] >= 0.5) for e in ev) / len(ev)
        noul_m = binary_metrics([truth[e] for e in ev],
                                ["attack" if lp[e]["noul"] >= 0.5 else "benign" for e in ev])
        analysis[fs + "_coherence"] = {
            "choice_vs_noul_contradiction_rate": round(contra, 4),
            "p_attack_ece": ece([(lp[e]["p_attack"], truth[e] == "attack") for e in ev]),
            "noul_head_as_classifier": {k: noul_m[k] for k in
                                        ("accuracy", "attack_f1", "false_positive_rate", "false_negative_rate")},
        }

    # --- FP-adjudication: can Laya veto an over-eager detector's false alarms
    #     WITHOUT suppressing real ones? Use logreg-compact (it produces FPs; RF ~0). ---
    lp = load("laya_preds_compact.json")
    lg = base_preds["compact"]["logreg"]
    fp = [e for e in lg if truth[e] == "benign" and lg[e] == "attack"]
    tp = [e for e in lg if truth[e] == "attack" and lg[e] == "attack"]
    rescued = sum(lp[e]["choice"] == "benign" for e in fp)
    damaged = sum(lp[e]["choice"] == "benign" for e in tp)
    analysis["fp_adjudication"] = {
        "over_eager_detector": "logreg_compact",
        "n_false_positives": len(fp), "laya_correctly_vetoed": rescued,
        "rescue_rate": round(rescued / len(fp), 4) if fp else None,
        "n_true_positives": len(tp), "laya_wrongly_vetoed_real_attacks": damaged,
        "damage_rate": round(damaged / len(tp), 4) if tp else None,
    }

    # --- disagreements: every flow Laya (compact) gets wrong, with both baselines' calls ---
    rf = base_preds["broad"]["random_forest"]
    with open(os.path.join(D, "laya_disagreements.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "truth", "laya_choice", "laya_p_attack", "laya_noul",
                    "rf_broad", "logreg_compact"])
        for e in lp:
            if lp[e]["choice"] != truth[e]:
                w.writerow([e, truth[e], lp[e]["choice"], lp[e]["p_attack"], lp[e]["noul"],
                            rf.get(e), lg.get(e)])

    json.dump(analysis, open(os.path.join(D, "analysis.json"), "w"), indent=2)
    print(json.dumps(analysis, indent=2))


if __name__ == "__main__":
    main()
