#!/usr/bin/env python3
"""Run Laya (zero-shot) over the SHARED 1000-flow test split, for both COMPACT
and BROAD feature sets. Saves per-flow predictions + runtime/memory facts.
No labels/identifiers in the prompt. Heavy + slow on CPU by design — we measure
exactly how heavy. Run in background; it checkpoints JSON at the end.
"""
import os, sys, time, json, resource
os.environ.setdefault("USE_TF", "0")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import common as C
from smoke_laya import QUESTIONS, MODEL, rss_mb

BATCH = 32
LAT_SAMPLE = 30  # single-call latency sample (candidate-only trickle latency)


def extract(res):
    a = res["answers"]
    tc = a["traffic_class"]
    return {"choice": tc["choice"],
            "p_attack": round(float(tc["probabilities"]["attack"]), 4),
            "conf": round(float(tc.get("answer_confidence", 0.0)), 4),
            "noul": round(float(a["is_malicious"]["noul"]), 4)}


def main():
    import laya
    test = pd.read_pickle(os.path.join(C.DATA, "test.pkl"))
    dev = os.environ.get("LAYA_DEVICE")  # None -> laya auto-detects (cuda if available)
    print(f"loading {MODEL} on {dev or 'auto (cuda if available)'}...", flush=True)
    t0 = time.time()
    agent = laya.load(MODEL, device=dev)
    runtime = {"model": MODEL, "device": dev or "auto", "load_time_s": round(time.time() - t0, 1),
               "rss_after_load_mb": round(rss_mb()), "n_test": len(test), "batch": BATCH}
    print(f"loaded in {runtime['load_time_s']}s, rss={runtime['rss_after_load_mb']}MB", flush=True)

    for fname, feats in [("compact", C.COMPACT), ("broad", C.BROAD)]:
        states = [C.row_to_state(r, feats) for _, r in test.iterrows()]

        # single-call latency percentiles (how a candidate-only trickle would feel)
        lat = []
        for s in states[:LAT_SAMPLE]:
            t = time.time(); agent.predict(s, QUESTIONS); lat.append((time.time() - t) * 1000)
        lat.sort()
        pct = lambda p: round(lat[min(len(lat) - 1, int(p * len(lat)))], 1)

        # batched throughput over the full split
        t = time.time()
        results = agent.predict_batch(states, QUESTIONS, batch_size=BATCH)
        wall = time.time() - t
        preds = {ev: extract(res) for ev, res in zip(test["event_id"], results)}
        json.dump(preds, open(os.path.join(C.DATA, f"laya_preds_{fname}.json"), "w"), indent=2)

        runtime[fname] = {
            "single_p50_ms": pct(0.50), "single_p95_ms": pct(0.95), "single_p99_ms": pct(0.99),
            "batch_wall_s": round(wall, 1),
            "batch_throughput_fps": round(len(states) / wall, 2),
            "peak_rss_mb": round(rss_mb()),
        }
        print(f"{fname}: {runtime[fname]}", flush=True)

    json.dump(runtime, open(os.path.join(C.DATA, "laya_runtime.json"), "w"), indent=2)
    print("DONE", json.dumps(runtime, indent=2), flush=True)


if __name__ == "__main__":
    main()
