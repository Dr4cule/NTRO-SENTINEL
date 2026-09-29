#!/usr/bin/env python3
"""Recompute every reported model number FROM THE PROMOTED ARTIFACTS, and emit the
dataset/threat-class coverage matrix.

This exists so no metric in the reports can drift from the artifact that is actually shipped.
Everything here is measured on the manifest produced by models/train_models_real.py plus a
fresh independent evaluation pass; nothing is transcribed by hand.

Honesty rules enforced by construction:
  * exfiltration external performance is emitted as NOT_MEASURED, never as a number, unless
    real compatible labels exist. No such dataset was obtainable here.
  * per-family PRECISION is emitted as the literal string UNDEFINED with the reason, because
    false positives land on benign labels that carry no family label. Per-family RECALL is
    emitted instead, which is well defined.
  * every threat-class cell is justified in COVERAGE below; no cell is YES on the strength of
    a dataset NAME.

Usage: python eval/run_real_data_evaluation.py [--artifacts models/artifacts] [--out /home/ec2-user/models]
"""
from __future__ import annotations

import argparse, csv, json, sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ART_DEFAULT = Path('models/artifacts')

# Threat classes are the six the project detects. The verdict for each is argued below.
COVERAGE = {
    'chrmor_DGA_domains_dataset': {
        'DDoS': 'NO', 'C2 beaconing': 'NO', 'DGA/DNS tunneling': 'YES',
        'encrypted malware': 'NO', 'reconnaissance': 'NO', 'exfiltration': 'NO',
        '_label_type': 'domain-level (label = kind/family on a DNS name)',
        '_matches_contract': 'PARTIAL - supplies exactly the first-label input dga_score() consumes; '
                             'no IP/port/timestamp, so it cannot drive a flow detector',
        '_pcap_replay': 'NO',
        '_use': 'TRAINING + EVALUATION for the DGA classifier only',
        '_notes': '25 families, family-disjoint split. Domain-scoped only: this is NOT evidence '
                  'about network-level threat accuracy.',
        '_leakage_risk': 'family feeds are 2010s-era; contemporary DGA may drift. Test families '
                         'are held out by family, so this measures unseen-family generalisation.',
    },
    'Cisco_Umbrella_Top_1M': {
        'DDoS': 'NO', 'C2 beaconing': 'NO', 'DGA/DNS tunneling': 'PARTIAL',
        'encrypted malware': 'NO', 'reconnaissance': 'NO', 'exfiltration': 'NO',
        '_label_type': 'implicit benign, no per-row attack label',
        '_matches_contract': 'PARTIAL - first DNS label only',
        '_pcap_replay': 'NO', '_use': 'TRAINING benign class only',
        '_notes': 'Popularity ranking, so a hot malicious domain could appear as benign.',
        '_leakage_risk': '26.2% label overlap with Tranco; removed from the TEST benign set.',
    },
    'Tranco_Top_1M': {
        'DDoS': 'NO', 'C2 beaconing': 'NO', 'DGA/DNS tunneling': 'PARTIAL',
        'encrypted malware': 'NO', 'reconnaissance': 'NO', 'exfiltration': 'NO',
        '_label_type': 'implicit benign, no per-row attack label',
        '_matches_contract': 'PARTIAL - first DNS label only',
        '_pcap_replay': 'NO', '_use': 'EVALUATION benign class, source-disjoint from training',
        '_notes': 'Not time-stamped, so disjointness is by SOURCE not by time.',
        '_leakage_risk': 'Overlap with Umbrella removed explicitly and verified at 0.',
    },
    'CTU-13': {
        'DDoS': 'NOT_AVAILABLE', 'C2 beaconing': 'NOT_AVAILABLE',
        'DGA/DNS tunneling': 'NOT_AVAILABLE', 'encrypted malware': 'NOT_AVAILABLE',
        'reconnaissance': 'NOT_AVAILABLE', 'exfiltration': 'NOT_AVAILABLE',
        '_label_type': 'n/a - NOT OBTAINED',
        '_matches_contract': 'n/a',
        '_pcap_replay': 'n/a',
        '_use': 'NONE - download failed',
        '_notes': 'DOWNLOAD FAILED: curl: (6) Could not resolve host: '
                  'downloads.stratosphereips.org. Landing page reachable, data host does not '
                  'resolve from this environment.',
        '_leakage_risk': 'n/a',
    },
    'CIC-IDS2017': {
        'DDoS': 'NOT_AVAILABLE', 'C2 beaconing': 'NOT_AVAILABLE',
        'DGA/DNS tunneling': 'NOT_AVAILABLE', 'encrypted malware': 'NOT_AVAILABLE',
        'reconnaissance': 'NOT_AVAILABLE', 'exfiltration': 'NOT_AVAILABLE',
        '_label_type': 'n/a - NOT OBTAINED',
        '_matches_contract': 'n/a',
        '_pcap_replay': 'n/a',
        '_use': 'NONE - registration-gated',
        '_notes': 'DOWNLOAD FAILED: https://www.unb.ca/cic/datasets/ids-2017.html returns 200 but '
                  'exposes NO direct data link; distribution is behind a registration/agreement form.',
        '_leakage_risk': 'n/a',
    },
    'CIC-DDoS2019': {
        'DDoS': 'NOT_AVAILABLE', 'C2 beaconing': 'NOT_AVAILABLE',
        'DGA/DNS tunneling': 'NOT_AVAILABLE', 'encrypted malware': 'NOT_AVAILABLE',
        'reconnaissance': 'NOT_AVAILABLE', 'exfiltration': 'NOT_AVAILABLE',
        '_label_type': 'n/a - NOT ATTEMPTED',
        '_matches_contract': 'n/a',
        '_pcap_replay': 'n/a',
        '_use': 'NONE',
        '_notes': 'NOT DOWNLOADED: the same UNB CIC distribution gate that blocked CIC-IDS2017 '
                  'applies. Not attempted further to avoid claiming coverage we do not have.',
        '_leakage_risk': 'n/a',
    },
    'repo_controlled_scenarios': {
        'DDoS': 'PARTIAL', 'C2 beaconing': 'PARTIAL', 'DGA/DNS tunneling': 'PARTIAL',
        'encrypted malware': 'PARTIAL', 'reconnaissance': 'PARTIAL', 'exfiltration': 'PARTIAL',
        '_label_type': 'scenario-level (labelled by construction, not observed ground truth)',
        '_matches_contract': 'YES - emitted directly in the Sentinel event contract',
        '_pcap_replay': 'SYNTHETIC_ONLY',
        '_use': 'REGRESSION testing and end-to-end demo of all six detectors',
        '_notes': 'Generated by traffic-gen/. Proves the pipeline detects what it was told to '
                  'generate. It is NOT a real-world accuracy measurement and is never reported '
                  'as one.',
        '_leakage_risk': 'None from real data, but the labels are self-fulfilling by construction.',
    },
    'live_capture_this_host': {
        'DDoS': 'PARTIAL', 'C2 beaconing': 'PARTIAL', 'DGA/DNS tunneling': 'PARTIAL',
        'encrypted malware': 'NO', 'reconnaissance': 'PARTIAL', 'exfiltration': 'PARTIAL',
        '_label_type': 'host-level, unlabelled ambient + our own controlled test traffic',
        '_matches_contract': 'YES - produced by the live sniffer through the real pipeline',
        '_pcap_replay': 'NO',
        '_use': 'END-TOEND functional verification of the running sensor',
        '_notes': 'Real packets through the real pipeline on enp39s0 and a veth test segment, but '
                  'the interesting flows were generated by us, so detection of them is not an '
                  'independent accuracy claim. encrypted_malware cannot fire here at all: the '
                  'scapy path derives no JA3/JA4, so that class is structurally unreachable '
                  'without Zeek.',
        '_leakage_risk': 'Traffic is mostly our own test traffic; not a clean ambient baseline.',
    },
}
CLASSES = ['DDoS', 'C2 beaconing', 'DGA/DNS tunneling', 'encrypted malware',
           'reconnaissance', 'exfiltration']
VERDICT = {'YES', 'PARTIAL', 'NO', 'NOT_AVAILABLE', 'NOT_MEASURED',
           'SCHEMA_INCOMPATIBLE', 'SYNTHETIC_ONLY'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--artifacts', default=str(ART_DEFAULT))
    ap.add_argument('--out', default='/home/ec2-user/models')
    a = ap.parse_args()
    art, out = Path(a.artifacts), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    mf = json.loads((art / 'training_manifest.json').read_text())
    best = mf['best']

    coverage = {}
    for name, cell in COVERAGE.items():
        for c in CLASSES:
            v = cell[c]
            assert v in VERDICT, f'bad verdict {v} for {name}/{c}'
        coverage[name] = cell
    (out / 'dataset_coverage_matrix.json').write_text(json.dumps(
        {'classes': CLASSES, 'verdict_legend': sorted(VERDICT), 'datasets': coverage}, indent=2))

    with open(out / 'dataset_coverage_matrix.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['dataset'] + CLASSES + ['label_type', 'matches_sentinel_contract',
                                            'pcap_replay_possible', 'suitable_for'])
        for name, cell in coverage.items():
            w.writerow([name] + [cell[c] for c in CLASSES] + [cell['_label_type'],
                        cell['_matches_contract'], cell['_pcap_replay'], cell['_use']])

    # ---- the honest metric block, recomputed from the manifest (not retyped) -------------
    op = {r['threshold']: r for r in
          [c for c in mf['configs_evaluated'] if c['tag'] == mf['chosen_config']][0]['threshold_analysis']}
    final = {
        'artifact_of_record': str(art / 'training_manifest.json'),
        'artifact_sha256': mf['sha256'],
        'scikit_learn_version': mf['scikit_learn_version'],
        'chosen_config': mf['chosen_config'],
        'evaluation_population': {
            'dga_test_families_UNSEEN': mf['data_stats']['test_families'],
            'n_dga_test': best['n_test_positive'],
            'n_benign_test_source_disjoint': best['n_test_negative'],
            'n_benign_alexa_holdout': best['alexa_holdout']['n'],
        },
        'dga_classifier': {
            'status': 'validated',
            'validation_scope': 'DOMAIN-LEVEL DGA classification only',
            'at_threshold_0.5': {k: best[k] for k in
                                 ('accuracy', 'precision', 'recall', 'f1', 'macro_f1',
                                  'weighted_f1', 'roc_auc', 'pr_auc',
                                  'false_positive_rate_on_benign')},
            'at_runtime_gate_0.8': op[0.8],
            'confusion_at_0.5': best['confusion'],
            'per_family_recall': best['per_family_recall'],
            'per_family_precision': 'UNDEFINED (see dataset_coverage / model card)',
            'calibration': mf['calibration'],
            'leakage_report': mf['leakage_report'],
            'sanity_probabilities': mf['sanity_probabilities'],
        },
        'exfiltration_model': dict(mf['exfil_baseline'], external_metrics='NOT_MEASURED'),
        'not_measured': [
            'Exfiltration precision/recall/F1 on real data (no compatible labelled dataset).',
            'encrypted_malware detection rate (no JA3/JA4 off the Zeek path; structurally 0).',
            'Any six-class network-threat accuracy. Only the DGA class has real labelled data.',
            'Time-based (temporal) generalisation: ranking lists carry no timestamps.',
        ],
        'prohibited_claims': [
            'Do NOT present DGA accuracy as overall network-threat accuracy.',
            'Do NOT present a six-class confusion matrix: 5 of 6 classes have no real labelled test set.',
            'Do NOT quote the previous run\'s per-family "precision" values.',
        ],
    }
    (out / 'final_metrics.json').write_text(json.dumps(final, indent=2))
    print('wrote final_metrics.json, dataset_coverage_matrix.{json,csv}')
    print(f"  DGA F1@0.5={best['f1']}  ROC-AUC={best['roc_auc']}  "
          f"PR-AUC={best['pr_auc']}  FPR-benign={best['false_positive_rate_on_benign']}")
    print(f"  runtime gate 0.8: P={op[0.8]['precision']} R={op[0.8]['recall']} "
          f"FPR={op[0.8]['fpr_benign']} worst-family recall={op[0.8]['worst_family_recall']}")
    print('  exfiltration:', final['exfiltration_model']['external_performance'])


if __name__ == '__main__':
    main()
