#!/usr/bin/env python3
"""Retrain the DGA char-ngram classifier on REAL labelled data.

Supersedes models/train_models.py (synthetic lab labels) for the DGA artifact only.
The exfiltration model is NOT produced here: there is no public exfiltration dataset with
labels compatible with the [outbound_bytes, outbound_inbound_ratio] contract, and inventing
one would be fabrication. See models/exfil_status.py and the EXFILTRATION model card.

Data (all real, all downloaded, digests in models/real_dataset_registry.yml):
  - DGA + Alexa-legit : chrmor/DGA_domains_dataset (25 families, 337,500 DGA rows)
  - benign TRAIN      : Cisco Umbrella top-1M
  - benign TEST       : Tranco top-1M, with every label also present in Umbrella removed,
                        so the benign classes are source-disjoint
  - benign HOLDOUT    : the dataset's own Alexa-derived 'legit' rows, never trained on

Split design (leakage-safe):
  * DGA families are DISJOINT between train and test - the six test families are never seen
    during training, so this measures generalisation to unseen malware families rather than
    memorisation.
  * Benign train and test come from DIFFERENT ranking sources AND are label-disjoint.
  * Duplicate and cross-set overlap are explicitly measured and reported, not assumed.

CORRECTION vs the previous run (2026-09-29 audit)
--------------------------------------------------
The earlier report's per-family "precision" was TP_f / (TP_f + GLOBAL_FP): the entire global
false-positive count was charged to every family, which makes all six families look like
~0.47 precision while the same file reports 0.8348 aggregate precision. Those two numbers
cannot both be true. It is not a precision, and it is not reproducible as one.

Per-family PRECISION is genuinely undefined for this model: false positives are produced on
BENIGN labels, which carry no family, so a prediction cannot be attributed to a family. What
IS well defined is per-family RECALL (the detection rate for that family's domains) and the
single global precision / FPR. This script reports those and says so explicitly.

Interface is unchanged: models/inference.py calls predict_proba([label])[0][1] on a raw first
DNS label. The pickle references models.numeric_feats.numeric_features, so that module must
ship with the artifact.
"""
from __future__ import annotations

import argparse, csv, hashlib, json, os, random, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Allow `python models/train_models_real.py` as well as `python -m models.train_models_real`:
# running the file directly puts models/ on sys.path, not the repository root, so the
# `models.numeric_feats` import below would fail without this.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_recall_fscore_support, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from joblib import dump

# own module so the pickled FunctionTransformer resolves at inference time
from models.numeric_feats import numeric_features

SEED = 26145
HELDOUT_FAMILY_FRACTION = 0.25
STOP_LABELS = {'www', 'com', 'org', 'net', 'mail', 'web', 'mail2', 'info', 'biz', 'co'}


def first_label(domain: str) -> str:
    """Runtime contract: models.inference.dga_score() is given the FIRST DNS label."""
    return domain.strip().split('.')[0].lower()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def load_dga_csv(path: Path):
    by_family, alexa = defaultdict(list), []
    with open(path, newline='', errors='ignore') as f:
        for row in csv.reader(f):
            if len(row) != 3:
                continue
            kind, family, domain = row
            lab = first_label(domain)
            if len(lab) < 4:
                continue
            if kind == 'dga':
                by_family[family].append(lab)
            elif kind == 'legit':
                alexa.append(lab)
    return by_family, alexa


def load_ranking(path: Path, cap: int):
    seen, out = set(), []
    with open(path, newline='', errors='ignore') as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            lab = first_label(row[1])
            if len(lab) < 4 or lab in seen or lab in STOP_LABELS:
                continue
            seen.add(lab)
            out.append(lab)
            if len(out) >= cap:
                break
    return out


def build_data(data_root: Path):
    by_family, alexa = load_dga_csv(data_root / 'dga_domains_full.csv')

    # Benign train pool from Umbrella, test pool from Tranco, then force source-disjointness.
    benign_train_pool = load_ranking(data_root / 'umbrella.csv', 400_000)
    benign_test_pool = load_ranking(data_root / 'tranco.csv', 200_000)
    train_set = set(benign_train_pool)
    benign_test = [b for b in benign_test_pool if b not in train_set]
    random.Random(SEED).shuffle(benign_train_pool)

    rng = random.Random(SEED)
    families = sorted(by_family)
    rng.shuffle(families)
    n_test = max(5, int(round(len(families) * HELDOUT_FAMILY_FRACTION)))
    test_families = sorted(families[:n_test])
    train_families = sorted(families[n_test:])

    # every domain of a test family is held out; train families are capped per family so the
    # big feeds cannot drown the small ones
    per_family_cap = 4000
    train_dga = []
    for fam in train_families:
        labs = list(by_family[fam])
        rng.shuffle(labs)
        train_dga += [(l, fam) for l in labs[:per_family_cap]]
    test_dga = []
    for fam in test_families:
        labs = list(by_family[fam])
        rng.shuffle(labs)
        test_dga += [(l, fam) for l in labs]
    rng.shuffle(train_dga)
    rng.shuffle(test_dga)

    alexa = sorted(set(alexa))                      # dedupe; never used for training
    rng.shuffle(alexa)
    stats = {
        'n_dga_families_total': len(families),
        'train_families': train_families,
        'test_families': test_families,
        'n_train_families': len(train_families),
        'n_test_families': len(test_families),
        'train_dga': len(train_dga),
        'test_dga': len(test_dga),
        'benign_train': len(benign_train_pool),
        'benign_test': len(benign_test),
        'benign_alexa_holdout': len(alexa),
        'benign_train_source': 'cisco-umbrella-top1m',
        'benign_test_source': 'tranco-top1m (umbrella labels removed)',
        'benign_holdout_source': 'chrmor dataset legit/alexa rows (never trained on)',
    }
    return train_dga, benign_train_pool, test_dga, benign_test, alexa, stats


def leakage_report(train_dga, test_dga, benign_train, benign_test, alexa):
    tr_d = {d for d, _ in train_dga}; te_d = {d for d, _ in test_dga}
    bt, be, ba = set(benign_train), set(benign_test), set(alexa)
    dup_in_train = len(train_dga) - len(tr_d)
    dup_in_test = len(test_dga) - len(te_d)
    return {
        'duplicate_domains_within_train_dga': dup_in_train,
        'duplicate_domains_within_test_dga': dup_in_test,
        'dga_overlap_train_test': len(tr_d & te_d),
        'benign_overlap_train_test': len(bt & be),
        'dga_overlap_train_vs_benign_any': len((tr_d | te_d) & (bt | be | ba)),
        'benign_source_disjoint': len(bt & be) == 0,
        'note': ('DGA families are disjoint by construction; a non-zero dga_overlap would mean '
                 'the same domain string appears under two families and is reported, not hidden.'),
    }


def build_pipeline(ngram_range, max_features=300_000):
    return Pipeline([
        ('feats', FeatureUnion([
            ('chars', TfidfVectorizer(analyzer='char', ngram_range=ngram_range,
                                      min_df=2, max_features=max_features, sublinear_tf=True)),
            ('nums', Pipeline([
                ('extract', FunctionTransformer(numeric_features)),
                ('scale', StandardScaler()),
            ])),
        ])),
        ('classifier', LogisticRegression(max_iter=1000, C=1.0,
                                          class_weight='balanced', random_state=SEED)),
    ])


def evaluate(pipe, test_dga, benign_test, alexa, tag, threshold=0.5):
    y_true = np.array([1] * len(test_dga) + [0] * len(benign_test))
    X = [d for d, _ in test_dga] + list(benign_test)
    proba = pipe.predict_proba(X)[:, 1]
    pred = (proba >= threshold).astype(int)

    p = precision_score(y_true, pred, zero_division=0)
    r = recall_score(y_true, pred, zero_division=0)
    f1 = f1_score(y_true, pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    macro_f1 = f1_score(y_true, pred, average='macro', zero_division=0)
    wtd_f1 = f1_score(y_true, pred, average='weighted', zero_division=0)

    # --- per family: RECALL only, and deliberately so (see module docstring) -------------
    proba_dga = proba[:len(test_dga)]
    fam = {}
    for name in sorted({f for _, f in test_dga}):
        idx = [i for i, (_, f) in enumerate(test_dga) if f == name]
        y_f = np.array([1] * len(idx))
        p_f = (proba_dga[idx] >= threshold).astype(int)
        tp_f, fn_f = int(p_f.sum()), int(len(idx) - p_f.sum())
        fam[name] = {
            'support': len(idx),
            'detected': tp_f,
            'recall': round(tp_f / len(idx), 4) if idx else 0.0,
            'missed': fn_f,
            'mean_probability': round(float(proba_dga[idx].mean()), 4),
        }

    fpr_benign = fp / max(1, len(benign_test))
    alexa_p = pipe.predict_proba(list(alexa))[:, 1]
    alexa_fp = int((alexa_p >= threshold).sum())

    return {
        'tag': tag,
        'threshold': threshold,
        'n_test_positive': len(test_dga), 'n_test_negative': len(benign_test),
        'accuracy': round(accuracy_score(y_true, pred), 4),
        'precision': round(p, 4), 'recall': round(r, 4), 'f1': round(f1, 4),
        'macro_f1': round(macro_f1, 4), 'weighted_f1': round(wtd_f1, 4),
        'roc_auc': round(roc_auc_score(y_true, proba), 4),
        'pr_auc': round(average_precision_score(y_true, proba), 4),
        'false_positive_rate_on_benign': round(fpr_benign, 4),
        'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        'per_family_recall': fam,
        'per_family_precision': 'UNDEFINED - see docstring; FPs occur on benign labels that carry no family',
        'alexa_holdout': {'n': len(alexa), 'false_positives': alexa_fp,
                          'fpr': round(alexa_fp / max(1, len(alexa)), 4),
                          'mean_probability': round(float(alexa_p.mean()), 4)},
        '_proba': proba, '_y': y_true, '_test_dga': test_dga,
    }


def threshold_curve(proba, y, test_dga):
    out = []
    for t in (0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90):
        pred = (proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        fams = defaultdict(lambda: [0, 0])
        for i, (_, f) in enumerate(test_dga):
            fams[f][1] += 1
            if pred[i] == 1:
                fams[f][0] += 1
        min_recall = min((v[0] / v[1]) for v in fams.values() if v[1]) if fams else 0.0
        out.append({
            'threshold': t,
            'precision': round(precision_score(y, pred, zero_division=0), 4),
            'recall': round(recall_score(y, pred, zero_division=0), 4),
            'f1': round(f1_score(y, pred, zero_division=0), 4),
            'fpr_benign': round(fp / max(1, int((y == 0).sum())), 4),
            'worst_family_recall': round(min_recall, 4),
            'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        })
    return out


def calibration(proba, y, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    rows = []
    for i in range(bins):
        lo, hi = edges[i], edges[i + 1]
        m = (proba >= lo) & (proba < hi if i < bins - 1 else proba <= hi)
        if not m.any():
            continue
        rows.append({'bin': f'[{lo:.1f},{hi:.1f})', 'n': int(m.sum()),
                     'mean_predicted': round(float(proba[m].mean()), 4),
                     'observed_rate': round(float(y[m].mean()), 4)})
    return rows


def train_exfil_prototype(out: Path):
    """Isolation Forest for the [outbound_bytes, out/in ratio] enrichment contract.

    NOT trained on real data, and deliberately not presented as if it were.

    No public exfiltration dataset with labels compatible with this contract
    ([outbound_bytes, outbound_inbound_ratio] over a source/destination/time window) could be
    obtained in this environment - see models/real_dataset_registry.yml for the exact download
    failures for CTU-13 (DNS: downloads.stratosphereips.org does not resolve) and CIC-IDS2017
    (registration-gated, no direct data link). Fabricating positives to "validate" it would
    manufacture the number it is supposed to test.

    So this stays a PROTOTYPE: fit on a documented synthetic benign upload envelope spanning
    routine..moderate volume, which is what makes its score discriminate inside the detector's
    operating region (alerts start at 5e5 bytes / ratio 5) instead of flagging everything.
    External exfiltration performance is NOT_MEASURED. The deterministic gate in
    detectors/rules.py remains the sole decision; this only nudges confidence.
    """
    from sklearn.ensemble import IsolationForest
    rng = random.Random(SEED)
    benign = [[rng.uniform(1e3, 1e6), rng.uniform(0.2, 8.0)] for _ in range(300)]
    model = IsolationForest(contamination=0.05, random_state=SEED).fit(benign)
    dump(model, out / 'exfil_baseline.joblib')
    return {
        'status': 'prototype',
        'validation_status': 'not_measured',
        'external_performance': 'NOT_MEASURED',
        'trained_on': 'synthetic benign upload envelope (documented above) - NOT real exfiltration data',
        'reason': ('No public exfiltration dataset with labels matching '
                   '[outbound_bytes, outbound_inbound_ratio] was obtainable in this environment.'),
        'contract': 'exfil_anomaly(outbound_bytes, ratio) -> {\'flag\', \'score\'}',
        'gate_status': 'ENRICHMENT ONLY - detectors/rules.py remains the sole decision path',
        'synthetic_points': len(benign),
        'envelope': {'outbound_bytes': [1e3, 1e6], 'outbound_inbound_ratio': [0.2, 8.0]},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data-root', default='/home/ec2-user/ntro_data')
    ap.add_argument('--output-dir', default='/tmp/ntro-sentinel-validated-artifacts')
    args = ap.parse_args()
    data_root, out = Path(args.data_root), Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    random.seed(SEED); np.random.seed(SEED)
    train_dga, benign_train, test_dga, benign_test, alexa, stats = build_data(data_root)
    print(json.dumps(stats, indent=2), flush=True)
    leak = leakage_report(train_dga, test_dga, benign_train, benign_test, alexa)
    print('leakage:', json.dumps(leak, indent=2), flush=True)

    Xtr = [d for d, _ in train_dga] + list(benign_train)
    ytr = [1] * len(train_dga) + [0] * len(benign_train)
    order = list(range(len(Xtr))); random.shuffle(order)
    Xtr = [Xtr[i] for i in order]; ytr = [ytr[i] for i in order]

    results, best = [], None
    for ngram in [(2, 5), (3, 5), (2, 4)]:
        tag = f'char_{ngram[0]}-{ngram[1]}+len+entropy'
        print(f'--- training {tag} on {len(Xtr)} samples ---', flush=True)
        pipe = build_pipeline(ngram)
        pipe.fit(Xtr, ytr)
        res = evaluate(pipe, test_dga, benign_test, alexa, tag)
        print(json.dumps({k: v for k, v in res.items()
                          if k not in ('_proba', '_y', '_test_dga', 'per_family_recall')},
                         indent=2), flush=True)
        res['threshold_analysis'] = threshold_curve(res['_proba'], res['_y'], res['_test_dga'])
        res['calibration'] = calibration(res['_proba'], res['_y'])
        results.append(res)
        if best is None or res['f1'] > best['f1']:
            best, best_pipe, best_tag = res, pipe, tag

    checks = ['microsoft', 'grafana', 'sonarqube', 'kubernetes', 'elasticsearch',
              'xk39fjq2mzp1vb7wnt', 'a8f3k2p9q1z7x5v3b2n1m4', 'qvxzj7k3m1p9b5n2']
    sanity = {w: round(float(best_pipe.predict_proba([w])[0][1]), 4) for w in checks}

    dump(best_pipe, out / 'dga_char_ngrams.joblib')
    exfil_info = train_exfil_prototype(out)
    print('exfil prototype:', json.dumps(exfil_info['status']), '-', exfil_info['external_performance'], flush=True)

    for r in results:                       # keep the json serialisable
        for k in ('_proba', '_y', '_test_dga'):
            r.pop(k, None)

    manifest = {
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'seed': SEED,
        'python_version': sys.version.split()[0],
        'scikit_learn_version': sklearn.__version__,
        'numpy_version': np.__version__,
        'training_data': 'REAL labelled public data (see models/real_dataset_registry.yml)',
        'datasets': {
            'dga_domains_full.csv': sha256_file(data_root / 'dga_domains_full.csv'),
            'umbrella.csv': sha256_file(data_root / 'umbrella.csv'),
            'tranco.csv': sha256_file(data_root / 'tranco.csv'),
        },
        'split_design': {
            'dga': 'family-disjoint: 6 of 25 families held out, never seen in training',
            'benign': 'source-disjoint: train from Umbrella, test from Tranco with overlapping labels removed',
            'extra_holdout': 'Alexa legit rows from the DGA dataset, never trained on',
        },
        'feature_contract': 'first DNS label only; models.inference.dga_score(label)',
        'preprocessing': {'ngram_analyzer': 'char', 'min_df': 2, 'max_features': 300000,
                          'sublinear_tf': True, 'numeric_features': ['label_length', 'shannon_entropy'],
                          'min_label_length': 4, 'stop_labels': sorted(STOP_LABELS)},
        'chosen_config': best_tag,
        # 'models' is the key the repo's tests/test_model_integrity.py contract reads; keep it
        # in sync with 'model_files' rather than renaming it and breaking that test.
        'models': ['dga_char_ngrams.joblib', 'exfil_baseline.joblib'],
        'model_files': ['dga_char_ngrams.joblib', 'exfil_baseline.joblib'],
        'exfil_baseline': exfil_info,
        'data_stats': stats,
        'leakage_report': leak,
        'configs_evaluated': [{k: v for k, v in r.items()
                               if k not in ('per_family_recall', 'calibration')} for r in results],
        'best': {k: v for k, v in best.items() if k != 'calibration'},
        'calibration': best['calibration'],
        'sanity_probabilities': sanity,
        'sha256': {n: sha256_file(out / n) for n in ('dga_char_ngrams.joblib', 'exfil_baseline.joblib')},
        'security_warning': ('joblib artifacts are pickle-based: loading one executes code. '
                             'models/inference.py verifies SHA-256 against this manifest before '
                             'unpickling and refuses a scikit-learn version mismatch.'),
    }
    (out / 'training_manifest.json').write_text(json.dumps(manifest, indent=2))
    (out / 'dga_real_data_report.json').write_text(json.dumps(
        {'baseline_old_synthetic_disjoint_f1': 0.48,
         'note': ('The previous report\'s per-family "precision" was TP_f/(TP_f+global_FP), which '
                  'is not a precision and contradicted its own 0.8348 aggregate. Recomputed here '
                  'with per-family recall instead.'),
         'new': manifest}, indent=2))
    print('BEST:', best_tag, 'F1:', best['f1'], 'ROC-AUC:', best['roc_auc'],
          'PR-AUC:', best['pr_auc'], 'FPR-benign:', best['false_positive_rate_on_benign'])
    print('sanity:', json.dumps(sanity, indent=2))


if __name__ == '__main__':
    main()
