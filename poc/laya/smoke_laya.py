#!/usr/bin/env python3
"""Minimal Laya smoke test — load the model the brief named, run ONE CIC flow
state through the controlled question schema, and MEASURE: model-load time
(incl. first-run download), peak RSS, and warm per-prediction latency.

CPU-only, in-process (never laya-serve). This is the go/no-go before scaling to
the full test split. Poor output here is a valid finding, not a bug to hide.
"""
import os, sys, time, json, resource
os.environ.setdefault("USE_TF", "0")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import common as C

MODEL = "convaiinnovations/laya-typed-decisions"

# Controlled, label-free question schema (no leak of the answer into the prompt).
QUESTIONS = {
    "traffic_class": {
        "type": "choice",
        "instructions": "Classify this one-directional network flow from its statistics.",
        "criteria": {
            "benign": "normal traffic: moderate packet/byte rates, typical packet sizes, "
                      "sessions that look complete and balanced",
            "attack": "malicious traffic such as a denial-of-service flood: abnormally high "
                      "packet or byte rates, very small or uniform packets, one-sided or "
                      "incomplete sessions",
        },
    },
    "is_malicious": {
        "type": "noul",
        "instructions": "Do these network flow statistics indicate a network attack "
                        "(such as denial-of-service) rather than benign traffic?",
    },
}


def rss_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0  # Linux: KB -> MB


def main():
    import laya
    row = pd.read_pickle(os.path.join(C.DATA, "test.pkl")).iloc[0]
    state = C.row_to_state(row, C.COMPACT)
    print("STATE (compact, label-free):")
    print(json.dumps(state, indent=2))
    print("true label:", row["y"])

    dev = os.environ.get("LAYA_DEVICE")  # None -> laya auto-detects (cuda if available)
    print(f"\nloading {MODEL} on {dev or 'auto (cuda if available)'} "
          "(first run downloads weights)...")
    t0 = time.time()
    agent = laya.load(MODEL, device=dev)
    load_s = time.time() - t0
    print(f"load_time_s={load_s:.1f}  rss_after_load_mb={rss_mb():.0f}")

    lat = []
    result = None
    for i in range(4):  # first call is cold (lazy init); rest are warm
        t = time.time()
        result = agent.predict(state, QUESTIONS)
        dt = (time.time() - t) * 1000
        lat.append(dt)
        print(f"  predict #{i} {dt:.0f} ms  ({'cold' if i == 0 else 'warm'})")

    print("\nRAW RESULT:")
    print(json.dumps(result, indent=2, default=str))
    print(f"\npeak_rss_mb={rss_mb():.0f}  cold_ms={lat[0]:.0f}  "
          f"warm_ms={sum(lat[1:]) / len(lat[1:]):.0f}")


if __name__ == "__main__":
    main()
