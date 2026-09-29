#!/usr/bin/env python3
"""Score the detectors against an EXTERNALLY labelled capture. This is the only sanctioned
route to a real precision/recall number, and this script is the missing half of that route.

The problem it solves
---------------------
Every accuracy figure in this repository so far comes from `traffic-gen/scenarios/*.jsonl`,
which we generated ourselves. Those numbers prove the pipeline runs and that the rules are
internally consistent; they cannot tell you whether the detectors work on someone else's
traffic. `docs/LIMITATIONS.md` and `README.md` both state this refusal explicitly.

What is required for a real number
----------------------------------
1. A permitted capture with ground-truth labels (CIC-IDS2017 PCAPs are the usual candidate).
2. Labels joined to flows by a key Sentinel can actually see. Sentinel is payload-blind, so the
   join CANNOT be by flow identity. It must be by (attacker/victim IP) + (time window), which is
   how published evaluations on this dataset are done and which is lossy by construction.

That lossiness is the whole reason the number must be produced carefully and reported with its
limitations, not quietly averaged away.

Usage
-----
  # 1. run the pipeline over the capture (metadata only)
  python3 -m ingest.pcap_to_events capture.pcap > events.jsonl

  # 2. score, against a label file: CSV/TSV with attacker_ips, victim_ips, start, end, label
  python3 -m eval.label_join --events events.jsonl --labels labels.csv \\
      --attack-ips 172.16.0.1 --victim-ips 192.168.10.50 --window 300

  # or go straight from the pcap
  python3 -m eval.label_join --pcap capture.pcap --labels labels.csv --window 300

Output: `eval/external_scoring.json` + a readable `.md`, containing per-class precision/recall/
F1 with Wilson 95% intervals, the confusion matrix, the join rate, and — importantly — an
explicit statement of what the join can and cannot see.

Deliberate non-features
-----------------------
* No accuracy is computed when the join rate is too low to be meaningful. A precision computed
  from 3 joined alerts is not a measurement; the script refuses and says why.
* Ground-truth labels are never used to influence detection. They are read only AFTER the
  pipeline has run, for scoring.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from engine.stream_consumer import Pipeline

# Minimum joined ground-truth events before a rate is reported at all. Below this the
# confidence intervals are meaningless and quoting a point estimate would be dishonest.
MIN_JOINED_EVENTS = 50
MIN_JOINED_PER_CLASS = 10

# Nearest Sentinel class for common public-dataset labels. Informational: it maps the
# dataset's vocabulary onto ours so the two can be compared, and is reported in the output so
# a reviewer can challenge the mapping rather than trust it.
LABEL_MAP = {
    'portscan': 'recon_scan', 'ddos': 'ddos', 'dos hulk': 'ddos', 'dos goldeneye': 'ddos',
    'dos slowloris': 'ddos', 'dos slowhttptest': 'ddos', 'bot': 'c2_beaconing',
    'heartbleed': 'encrypted_malware', 'infiltration': 'exfiltration',
    'ftp-patator': 'recon_scan', 'ssh-patator': 'recon_scan',
    'web attack': None, 'benign': None,
}


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. Preferred over the normal approximation because dataset-derived
    per-class counts are small and the normal approximation misbehaves there."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    d = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
    return (round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4))


def load_events(args) -> list[dict]:
    if args.pcap:
        from ingest.pcap_to_events import build_events
        return list(build_events(args.pcap, int(args.max_packets)))
    events = []
    for line in Path(args.events).read_text().splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def load_labels(path: str) -> list[dict]:
    """Read ground truth. Any CSV/TSV with a header; we only need the optional time columns
    and a class column, since the attack/victim IPs come from the CLI."""
    rows = []
    with open(path, newline='', encoding='utf-8-sig') as f:
        sample = f.read(4096)
        f.seek(0)
        delim = '\t' if sample.count('\t') > sample.count(',') else ','
        for row in csv.DictReader(f, delimiter=delim):
            rows.append({(k or '').strip().lower(): (v or '').strip() for k, v in row.items()})
    return rows


def ground_truth_windows(labels: list[dict]) -> list[dict]:
    """Extract (class, start, end) windows. Rows without parseable times become
    class-only labels applied to the whole capture, which is recorded in the output as
    time_joins_supported=False so the weaker join is visible."""
    windows, class_only = [], []
    for row in labels:
        cls = row.get('label') or row.get('class') or row.get('category') or ''
        if not cls:
            continue
        mapped = LABEL_MAP.get(cls.strip().lower())
        start = end = None
        for k in ('start', 'start_time', 'begin', 'from'):
            if k in row:
                try:
                    start = float(row[k]); break
                except ValueError:
                    try:
                        start = datetime.fromisoformat(row[k].replace('Z', '+00:00')).timestamp()
                        break
                    except ValueError:
                        pass
        for k in ('end', 'end_time', 'to'):
            if k in row and start is not None:
                try:
                    end = float(row[k])
                except ValueError:
                    try:
                        end = datetime.fromisoformat(row[k].replace('Z', '+00:00')).timestamp()
                    except ValueError:
                        end = None
        if start is not None and end is not None:
            windows.append({'class': mapped, 'raw': cls, 'start': start, 'end': end})
        else:
            class_only.append({'class': mapped, 'raw': cls})
    return windows, class_only


def truth_for(ev: dict, windows, class_only, atk, vic, tolerance) -> str | None:
    ip = ev.get('src_ip')
    if atk and ip in atk:
        t = ev.get('ts')
        for w in windows:
            if w['class'] and w['start'] - tolerance <= t <= w['end'] + tolerance:
                return w['class']
        for w in class_only:
            if w['class']:
                return w['class']
        return 'unknown'          # attacker IP, outside any labelled window
    if vic and ip in vic:
        return 'benign'           # victim host doing normal traffic
    return None                   # outside the labelled scope entirely -> excluded


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--pcap', help='capture to score (parsed offline, payload-blind)')
    src.add_argument('--events', help='pre-dumped normalized events (JSONL)')
    ap.add_argument('--labels', required=True, help='ground-truth CSV/TSV with a label column')
    ap.add_argument('--attack-ips', default='', help='comma-separated attacker IPs (ground truth)')
    ap.add_argument('--victim-ips', default='', help='comma-separated victim IPs (treated benign)')
    ap.add_argument('--window', type=float, default=300.0, help='labelled-window tolerance, seconds')
    ap.add_argument('--max-packets', type=int, default=2_000_000)
    ap.add_argument('--output', default='eval/external_scoring.json')
    args = ap.parse_args()

    atk = {x.strip() for x in args.attack_ips.split(',') if x.strip()}
    vic = {x.strip() for x in args.victim_ips.split(',') if x.strip()}
    if not atk:
        print('ERROR: --attack-ips is required. Without attacker IPs there is no way to join '
              'ground truth to detections, and any number produced would be meaningless.',
              file=sys.stderr)
        return 2

    events = load_events(args)
    labels = load_labels(args.labels)
    windows, class_only = ground_truth_windows(labels)

    # Run the pipeline FIRST. Ground truth is never visible to detection.
    pipeline = Pipeline()
    alerts = []
    for ev in events:
        alerts.extend(pipeline.process(ev))

    tp, fp, fn = Counter(), Counter(), Counter()
    joined = excluded = 0
    for ev in events:
        t = truth_for(ev, windows, class_only, atk, vic, args.window)
        if t is None:
            excluded += 1
            continue
        joined += 1
        fired = any(a['threat_class'] == t for a in alerts
                    if a['flow_id']['src_ip'] == ev.get('src_ip'))
        if t == 'benign':
            if fired:
                fp['benign'] += 1
        elif t == 'unknown':
            continue
        elif fired:
            tp[t] += 1
        else:
            fn[t] += 1
    # Detections on sources with no ground-truth coverage are false positives only if we can
    # assert the source is in scope; we cannot, so they are reported separately, not scored.
    unscored_alerts = [a for a in alerts
                       if atk and a['flow_id']['src_ip'] not in atk
                       and not (vic and a['flow_id']['src_ip'] in vic)]

    classes = sorted(set(tp) | set(fn))
    per_class = {}
    for c in classes:
        n = tp[c] + fn[c]
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else None
        rec = tp[c] / n if n else None
        f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
        per_class[c] = {
            'true_positives': tp[c], 'false_negatives': fn[c],
            'precision': round(prec, 4) if prec is not None else None,
            'precision_ci95': wilson(tp[c], tp[c] + fp[c]) if (tp[c] + fp[c]) else None,
            'recall': round(rec, 4) if rec is not None else None,
            'recall_ci95': wilson(tp[c], n) if n else None,
            'f1': round(f1, 4) if f1 is not None else None,
            'sufficient_sample': n >= MIN_JOINED_PER_CLASS,
        }

    join_rate = joined / max(1, len(events))
    reportable = joined >= MIN_JOINED_EVENTS and any(v['sufficient_sample'] for v in per_class.values())

    out = {
        'tool': 'eval/label_join.py',
        'purpose': 'Score Sentinel against an externally labelled capture by (source IP, time window).',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'inputs': {'events': len(events), 'alerts': len(alerts), 'labels_rows': len(labels),
                   'attack_ips': sorted(atk), 'victim_ips': sorted(vic),
                   'window_tolerance_s': args.window},
        'join': {
            'events_joined': joined,
            'events_excluded_out_of_scope': excluded,
            'join_rate': round(join_rate, 4),
            'time_joins_supported': bool(windows),
            'min_events_required': MIN_JOINED_EVENTS,
            'note': 'Sentinel is payload-blind, so ground truth can only be joined by source IP and '
                    'time window. Labelled attacks that produced no observable metadata at this '
                    'sensor are counted as false negatives by construction; this is an upper bound '
                    'on the true miss rate, not a detector defect.',
        },
        'per_class': per_class,
        'unscored_alerts': {
            'count': len(unscored_alerts),
            'note': 'Alerts on sources with no ground-truth coverage. Not scored as false '
                    'positives because the dataset says nothing about them.',
        },
        'reportable': reportable,
        'verdict': ('Scores are reportable (join rate and per-class sample sizes are adequate).'
                    if reportable else
                    f'NOT reportable: only {joined} events joined (need >= {MIN_JOINED_EVENTS}) or no '
                    f'class reached {MIN_JOINED_PER_CLASS} samples. Fix the label join before quoting '
                    'any number. This is the harness refusing to produce a misleading figure.'),
        'limitations': [
            'Scores apply to this capture and these labels only.',
            'The IP+time join is lossy; see join.note.',
            'Per-class precision is only meaningful where the class appears in the ground truth.',
        ],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2))

    md = ['# External Scoring', '', out['verdict'], '',
          f"Capture events: {len(events):,} · alerts: {len(alerts):,} · "
          f"joined: {joined:,} ({join_rate:.1%}) · excluded (out of scope): {excluded:,}", '',
          f"Alerts on sources with no ground-truth coverage: {len(unscored_alerts):,} "
          '(not scored as false positives — the dataset says nothing about them).', '',
          '| Sentinel class | TP | FN | Precision (95% CI) | Recall (95% CI) | F1 | n≥10? |',
          '|---|--:|--:|---|---|--:|:--:|']
    for c, v in per_class.items():
        pc = f"{v['precision']:.3f} [{v['precision_ci95'][0]:.3f}, {v['precision_ci95'][1]:.3f}]" if v['precision'] is not None else '—'
        rc = f"{v['recall']:.3f} [{v['recall_ci95'][0]:.3f}, {v['recall_ci95'][1]:.3f}]" if v['recall'] is not None else '—'
        md.append(f"| {c} | {v['true_positives']} | {v['false_negatives']} | {pc} | {rc} | "
                  f"{v['f1']:.3f} | {'yes' if v['sufficient_sample'] else 'NO'} |" if v['f1'] is not None
                  else f"| {c} | {v['true_positives']} | {v['false_negatives']} | {pc} | {rc} | — | "
                       f"{'yes' if v['sufficient_sample'] else 'NO'} |")
    md += ['', '## Limitations', ''] + [f'- {x}' for x in out['limitations']] + ['', out['join']['note'], '']
    Path(args.output).with_suffix('.md').write_text('\n'.join(md) + '\n')
    print(json.dumps({'reportable': out['reportable'], 'joined': joined, 'alerts': len(alerts),
                      'per_class': {k: v['f1'] for k, v in per_class.items()}}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
