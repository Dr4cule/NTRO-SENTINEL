#!/usr/bin/env python3
"""Shared config + helpers for the Laya POC. Read-only w.r.t. the CSV; imports
NOTHING from the production SentinelFlow packages, so it cannot alter them.

Feature-selection rationale lives in feature_selection.md.
"""
import os, re
import numpy as np, pandas as pd

CSV = os.environ.get(  # on Windows: set CIC_CSV to your dataset path
    "CIC_CSV", "/home/arshlaan/Downloads/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
SEED = 42

# --- feature sets (exact CSV names, no Destination Port -> see feature_selection.md) ---
COMPACT = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Packet Length Mean", "Packet Length Std", "Down/Up Ratio",
]
BROAD = COMPACT + [
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Fwd Packet Length Max", "Bwd Packet Length Max",
    "Flow IAT Max", "Flow IAT Min", "Fwd IAT Mean", "Bwd IAT Mean",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Average Packet Size", "SYN Flag Count", "ACK Flag Count", "RST Flag Count",
    "FIN Flag Count", "PSH Flag Count", "URG Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Subflow Fwd Bytes", "Subflow Bwd Bytes", "act_data_pkt_fwd",
]
# Never fed to any model: the target and the near-label identifier.
EXCLUDED = ["Label", "Destination Port", "Fwd Header Length.1"]
LABEL_MAP = {"BENIGN": "benign", "DDoS": "attack"}   # binary normalization


def _snake(name):
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_").replace("_s", "_per_s") \
        if name.endswith("/s") else re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


STATE_KEYS = {c: _snake(c) for c in BROAD}


def load_selected(cols):
    """Read only the needed columns (low memory), strip header whitespace,
    replace inf with NaN, drop rows missing any selected feature, drop exact
    duplicate flows (prevents train/test leakage of identical rows)."""
    raw = pd.read_csv(CSV, nrows=0).columns
    strip_map = {c.strip(): c for c in raw}
    need = [strip_map[c] for c in cols + ["Label"]]
    df = pd.read_csv(CSV, usecols=need)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=cols)
    df["y"] = df["Label"].str.strip().map(LABEL_MAP)
    df = df.dropna(subset=["y"]).drop_duplicates(subset=cols).reset_index(drop=True)
    df["event_id"] = ["cic-%06d" % i for i in range(len(df))]
    return df


def row_to_state(row, feats):
    """Compact structured state for Laya: readable key -> rounded number.
    No label, no port, no identifier."""
    out = {}
    for c in feats:
        v = row[c]
        out[STATE_KEYS[c]] = round(float(v), 4) if abs(float(v)) < 1e6 else round(float(v), 1)
    return out


def state_to_text(state):
    """Render a state dict as compact 'key: value' lines (encoder-friendly)."""
    head = "One-directional network flow statistics (no payload inspected):"
    return head + "\n" + "\n".join(f"{k}: {v}" for k, v in state.items())


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    df = load_selected(BROAD)
    print("clean rows:", len(df), "| class balance:", df["y"].value_counts().to_dict())
    r = df.iloc[0]
    print("example compact state:")
    import json
    print(json.dumps(row_to_state(r, COMPACT), indent=2))
