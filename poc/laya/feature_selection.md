# Feature selection — Laya POC (isolated, read-only on the CSV)

Dataset: `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (CIC-IDS2017).
225,745 rows, 79 columns, labels `DDoS` (56.7%) / `BENIGN` (43.3%). After
dropping inf/NaN and exact-duplicate flows: **220,282 clean rows**
(attack 128,013 / benign 92,269). See `dataset_report.json`.

Both the baseline and Laya are fed the **exact same** numeric features (no label,
no identifier). Two feature sets are tested so we can see whether more context
helps or hurts Laya's zero-shot reasoning.

## COMPACT (12) — one-way-friendly summary
`Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`,
`Total Length of Fwd Packets`, `Total Length of Bwd Packets`, `Flow Bytes/s`,
`Flow Packets/s`, `Flow IAT Mean`, `Flow IAT Std`, `Packet Length Mean`,
`Packet Length Std`, `Down/Up Ratio`.

## BROAD (38) — COMPACT + 26 richer stats
Per-direction packet-length mean/std/max, flow/fwd/bwd IAT extras, per-direction
packet rates, min/max/avg packet size, TCP flag counts
(SYN/ACK/RST/FIN/PSH/URG), init window bytes (fwd/bwd), subflow bytes,
`act_data_pkt_fwd`.

## EXCLUDED — and why (anti-cheating)
- **`Label`** — the target. Feeding it would be cheating.
- **`Destination Port`** — *near-label leak in THIS file*. The only attack here
  is an HTTP DDoS flood, overwhelmingly to port 80, while benign traffic is
  spread across many ports. A model keying on "port == 80" would score high here
  and generalise to nothing. Excluded from **both** sets on purpose.
- **`Fwd Header Length.1`** — exact duplicate of `Fwd Header Length` (CICFlowMeter
  artifact); dropping avoids a redundant, confusing signal.
- **Bulk columns** (`Fwd/Bwd Avg Bytes/Packets/Bulk Rate`) — effectively constant
  zero in this capture; no signal, only noise.
- Flow ID / source & destination IP / source port / timestamp — **not present**
  in this ISCX CSV variant, so nothing to strip there; the inspector's leak list
  still guards against them if a future file has them.

## Honest caveat: bidirectional source vs one-way target
CIC-IDS2017 features are **bidirectional** (fwd *and* bwd). SentinelFlow in
production is **one-way / passive**. This POC uses the CSV's bidirectional
features (that is what the labelled data offers) to benchmark Laya fairly against
a conventional model, but a real one-way deployment would only have forward-side
stats. This is a genuine domain mismatch and is called out in `results.md`, not
papered over. COMPACT leans on totals/rates (closer to one-way-derivable);
BROAD deliberately includes backward-direction fields to test the richer case.
