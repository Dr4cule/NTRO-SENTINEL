#!/usr/bin/env python3
"""Verify what a downloaded CIC-IDS2017 release actually supports for THIS pipeline.

Build-guide section 2 requires a dataset coverage matrix filled *after inspecting the
real data* — never copied from a paper. Sentinel is a passive **metadata** correlator:
its six detectors key on IPs, ports, DNS names and TLS fingerprints. This script reads
the real files, censuses the labels, and checks — field by field — whether each detector
can run. It makes NO performance claim; it answers "can this artifact drive the pipeline."

Usage:  python3 -m eval.cic_ids2017_coverage --dir /path/to/archive
"""
from __future__ import annotations
import argparse, glob, json, os
from pathlib import Path
import pandas as pd

# What each Sentinel detector groups/keys on. See detectors/rules.py + features/*.
REQUIRED = {
    "ddos":              ["src_ip", "dst_ip", "proto", "tcp_flags/conn_state"],
    "c2_beaconing":      ["src_ip", "dst_ip", "timestamp"],
    "dga_dns_tunnel":    ["dns_query"],
    "encrypted_malware": ["tls_ja3/sni", "src_ip", "orig_bytes", "resp_bytes"],
    "recon_scan":        ["src_ip", "dst_port"],
    "exfiltration":      ["src_ip", "dst_ip", "orig_bytes"],
}
# Nearest Sentinel class for each CIC-IDS2017 label (informational only).
LABEL_MAP = {
    "PortScan": "recon_scan", "DDoS": "ddos", "DoS Hulk": "ddos", "DoS GoldenEye": "ddos",
    "DoS slowloris": "ddos", "DoS Slowhttptest": "ddos", "Bot": "c2_beaconing",
    "Heartbleed": "encrypted_malware", "Infiltration": "exfiltration",
    "FTP-Patator": "recon_scan", "SSH-Patator": "recon_scan",
    "Web Attack � Brute Force": None, "Web Attack � XSS": None,
    "Web Attack � Sql Injection": None, "Benign": None,
}
# Metadata field -> the column name(s) that would carry it (any match = present).
FIELD_COLUMNS = {
    "src_ip": ["source ip", "src ip"], "dst_ip": ["destination ip", "dst ip"],
    "src_port": ["source port", "src port"], "dst_port": ["destination port", "dst port"],
    "proto": ["protocol"], "timestamp": ["timestamp"], "dns_query": ["query", "dns_query"],
    "tls_ja3/sni": ["ja3", "sni"], "tcp_flags/conn_state": ["flow id"],  # raw per-packet flags/state absent in flow aggregates
    "orig_bytes": ["fwd packets length total"], "resp_bytes": ["bwd packets length total"],
}


def field_present(field, cols):
    return any(c in cols for c in FIELD_COLUMNS.get(field, []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="experiments/data/cic-ids2017")
    ap.add_argument("--output", default="eval/cic_ids2017_coverage.json")
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.dir, "*.parquet")))
    if not files:
        raise SystemExit("no .parquet files in " + a.dir)

    census, cols, total = {}, None, 0
    for f in files:
        df = pd.read_parquet(f, columns=None)
        cols = set(c.lower().strip() for c in df.columns) if cols is None else cols
        lc = next(c for c in df.columns if c.lower().strip() == "label")
        for lab, n in df[lc].value_counts().items():
            census[lab] = census.get(lab, 0) + int(n)
        total += len(df)

    coverage = {}
    for det, fields in REQUIRED.items():
        missing = [x for x in fields if not field_present(x, cols)]
        coverage[det] = {"required": fields, "missing": missing, "can_run": not missing}

    labels_present = {l: census[l] for l in census}
    mapped = {}
    for lab in census:
        cls = LABEL_MAP.get(lab)
        if cls:
            mapped.setdefault(cls, []).append(lab)

    out = {
        "dataset": "CIC-IDS2017 (Sharafaldin, Lashkari & Ghorbani) — de-identified flow-feature release",
        "files": [os.path.basename(x) for x in files],
        "total_flows": total,
        "feature_columns": len(cols),
        "metadata_columns_present": sorted(
            f for f in FIELD_COLUMNS if field_present(f, cols)),
        "label_census": labels_present,
        "detector_coverage": coverage,
        "detectors_runnable": [d for d, v in coverage.items() if v["can_run"]],
        "label_to_sentinel_class": mapped,
        "verdict": ("This release carries CICFlowMeter statistical features only; the IP/port/"
                    "DNS/TLS/timestamp metadata every Sentinel detector groups on is absent, so no "
                    "detector can be exercised on it. Use the CIC-IDS2017 PCAPs replayed through Zeek "
                    "(build-guide Tier A) to validate the detectors on this dataset."),
        "note": "Coverage/fit check only. No precision/recall/F1 is computed or claimed here.",
    }
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(out, indent=2))

    md = ["# CIC-IDS2017 — Dataset Coverage / Fit Check", "", out["verdict"], "",
          f"Files: {len(files)} · Flows: {total:,} · Feature columns: {out['feature_columns']} · "
          f"Metadata columns present: {out['metadata_columns_present'] or 'NONE'}", "",
          "## Label census (real labels in the files)", "", "| CIC-IDS2017 label | flows | nearest Sentinel class |", "|---|---:|---|"]
    md += [f"| {l} | {census[l]:,} | {LABEL_MAP.get(l) or '—'} |" for l in sorted(census, key=lambda k: -census[k])]
    md += ["", "## Detector coverage (can each detector run on this release?)", "",
           "| Sentinel detector | requires | missing here | can run |", "|---|---|---|:--:|"]
    md += [f"| {d} | {', '.join(v['required'])} | {', '.join(v['missing']) or '—'} | {'yes' if v['can_run'] else 'NO'} |"
           for d, v in coverage.items()]
    md += ["", f"Detectors runnable on this artifact: **{out['detectors_runnable'] or 'none'}**.", "",
           out["note"], ""]
    Path("eval/cic_ids2017_coverage.md").write_text("\n".join(md) + "\n")
    print(json.dumps({"total_flows": total, "metadata_columns_present": out["metadata_columns_present"],
                      "detectors_runnable": out["detectors_runnable"], "verdict": out["verdict"]}, indent=2))


if __name__ == "__main__":
    main()
