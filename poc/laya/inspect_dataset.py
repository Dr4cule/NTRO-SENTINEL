#!/usr/bin/env python3
"""POC step 1 — inspect the CIC-IDS2017 CSV without loading it all into RAM.

Chunked pass -> poc/laya/dataset_report.json + label_mapping.json.
Runs on system python (pandas present). Touches NO production code, reads the
CSV read-only. See section 1/6 of the task brief.
"""
import json, os
from collections import Counter
import numpy as np, pandas as pd

CSV = "/home/arshlaan/Downloads/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
OUT = os.path.dirname(os.path.abspath(__file__))
CHUNK = 50000

# Identifiers / target that must never be fed to the model (would let it cheat).
# Ports are handled separately in feature_selection.md (borderline), not here.
LEAK_COLS = {"flow id", "source ip", "src ip", "destination ip", "dst ip",
             "source port", "src port", "timestamp", "label"}

def norm(c):
    return c.strip().lower()

def main():
    header = list(pd.read_csv(CSV, nrows=0).columns)
    ncols = [norm(c) for c in header]
    label_col = header[ncols.index("label")] if "label" in ncols else header[-1]

    rows = 0
    nchunks = 0
    nan = Counter()
    inf = Counter()
    labels = Counter()
    numeric_full = Counter()   # chunks in which the column parsed fully numeric
    seen = set()
    dups = 0

    for chunk in pd.read_csv(CSV, chunksize=CHUNK):
        nchunks += 1
        rows += len(chunk)
        labels.update(chunk[label_col].astype(str).str.strip())
        for c in chunk.columns:
            s = chunk[c]
            nan[c] += int(s.isna().sum())
            num = pd.to_numeric(s, errors="coerce")
            arr = num.to_numpy(dtype="float64", na_value=np.nan)
            inf[c] += int(np.isinf(arr).sum())
            if s.notna().sum() > 0 and num.notna().sum() == s.notna().sum():
                numeric_full[c] += 1
        h = pd.util.hash_pandas_object(chunk, index=False)
        for v in h.to_numpy():
            if v in seen:
                dups += 1
            else:
                seen.add(v)

    numeric_cols = [c for c in header if numeric_full[c] == nchunks]
    non_numeric = [c for c in header if c not in numeric_cols]
    candidates = [c for c in numeric_cols if norm(c) not in LEAK_COLS]
    label_map = {orig: orig.strip().upper() for orig in sorted(labels)}

    report = {
        "csv_path": CSV,
        "file_size_bytes": os.path.getsize(CSV),
        "total_rows": rows,
        "total_columns": len(header),
        "columns": [c.strip() for c in header],
        "label_column": label_col.strip(),
        "label_counts": dict(labels.most_common()),
        "label_percent": {k: round(100 * v / rows, 4) for k, v in labels.most_common()},
        "unique_labels": sorted(labels),
        "class_imbalance_ratio": round(max(labels.values()) / max(1, min(labels.values())), 2),
        "missing_values_total": int(sum(nan.values())),
        "columns_with_missing": {c.strip(): nan[c] for c in header if nan[c]},
        "infinite_values_total": int(sum(inf.values())),
        "columns_with_inf": {c.strip(): inf[c] for c in header if inf[c]},
        "duplicate_rows": dups,
        "numeric_columns": [c.strip() for c in numeric_cols],
        "non_numeric_columns": [c.strip() for c in non_numeric],
        "candidate_feature_columns": [c.strip() for c in candidates],
        "excluded_as_leak_or_id": sorted({c.strip() for c in header if norm(c) in LEAK_COLS}),
    }
    with open(os.path.join(OUT, "dataset_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(OUT, "label_mapping.json"), "w") as f:
        json.dump(label_map, f, indent=2)

    summary = {k: report[k] for k in ("total_rows", "total_columns", "label_counts",
               "label_percent", "class_imbalance_ratio", "missing_values_total",
               "infinite_values_total", "duplicate_rows", "unique_labels")}
    print(json.dumps(summary, indent=2))
    print(f"candidate features: {len(candidates)} | non-numeric: {[c.strip() for c in non_numeric]}")

if __name__ == "__main__":
    main()
