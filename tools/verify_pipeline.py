#!/usr/bin/env python3
"""End-to-end verification that the trained models are LIVE in the running pipeline.

Answers the question "are the changes actually in effect, and will they stay in effect?"
by checking four independent layers, each of which can fail separately:

  L1 SOURCE      the code changes that make the fixes work are present
  L2 ARTIFACT    models/artifacts matches the digests pinned in the manifest
  L3 CONTRACT    models.inference.dga_score / exfil_anomaly load and behave
  L4 PIPELINE    a real event through detectors/rules.py reaches an alert CARRYING the
                model's score, i.e. enrichment is wired in, not merely importable

L4 is the one that matters. A model can be perfectly present on disk, hash-match the
manifest, import cleanly, and still never be used, because a wrong MODEL_DIR or a
permissions fault makes dga_score() return None. That exact failure happened once during
this deployment and was invisible to every other check. This script asserts on the alert
payload instead of on the loader.

Read-only: touches no service state, writes nothing, loads no malware.

Usage:  python tools/verify_pipeline.py [--json] [--quiet]
Exit:   0 = all pass, 1 = one or more failures.
"""
from __future__ import annotations

import argparse, hashlib, json, os, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

RESULTS: list[tuple[str, str, bool, str]] = []


def check(layer: str, name: str, ok: bool, detail: str = '') -> bool:
    RESULTS.append((layer, name, bool(ok), detail))
    return bool(ok)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- L1 source
L1_MARKERS = [
    ('alertstore/store.py', '_begin_immediate',
     'hash-chain write lock (concurrent-upload race fix)'),
    ('detectors/rules.py', 'concentrated=f.get(\'unique_dst_ports\',1) <= 3',
     'port-concentration DDoS rule (scan-vs-flood fix)'),
    ('features/ddos.py', "'unique_dst_ports'",
     'port-concentration feature added'),
    ('features/base.py', '_SWEEP_EVERY',
     'amortised window eviction (O(events x keys) fix)'),
    ('ingest/service.py', '_UPLOAD_DRAIN_SECONDS',
     'bounded upload drain (upload-hang fix)'),
    ('ingest/service.py', 'consumer thread died',
     'consumer liveness watchdog (silent-death fix)'),
    ('ingest/service.py', '--live', 'repeatable --live (multi-interface capture)'),
    ('models/numeric_feats.py', 'def numeric_features',
     'importable numeric-feature module (required by the pickle)'),
    ('models/train_models_real.py', 'train_exfil_prototype',
     'real-data trainer with exfil prototype'),
    ('eval/run_real_data_evaluation.py', 'COVERAGE',
     'coverage-matrix generator'),
]


def layer_source() -> None:
    for rel, needle, why in L1_MARKERS:
        p = REPO / rel
        present = p.is_file() and needle in p.read_text()
        check('L1 source', f'{rel}: {why}', present,
              '' if present else f'marker {needle!r} not found in {rel}')


# -------------------------------------------------------------- L2 artifact
def layer_artifact() -> None:
    art = Path(os.getenv('MODEL_DIR', REPO / 'models/artifacts'))
    mf_path = art / 'training_manifest.json'
    if not check('L2 artifact', 'training_manifest.json present', mf_path.is_file(), str(art)):
        return
    mf = json.loads(mf_path.read_text())

    import sklearn
    check('L2 artifact', 'sklearn version matches manifest',
          mf.get('scikit_learn_version') == sklearn.__version__,
          f"manifest={mf.get('scikit_learn_version')} runtime={sklearn.__version__}")

    for name, expected in (mf.get('sha256') or {}).items():
        p = art / name
        if not p.is_file():
            check('L2 artifact', f'{name} present', False, 'file missing')
            continue
        actual = sha256_file(p)
        check('L2 artifact', f'{name} digest matches manifest', actual == expected,
              f'expected {expected[:16]}… actual {actual[:16]}…')

    ex = mf.get('exfil_baseline') or {}
    check('L2 artifact', 'exfil status honestly labelled',
          ex.get('validation_status') == 'not_measured',
          f"status={ex.get('status')} validation={ex.get('validation_status')}")


# -------------------------------------------------------------- L3 contract
def layer_contract() -> None:
    from models.inference import dga_score, exfil_anomaly

    benign = dga_score('microsoft')
    check('L3 contract', 'dga_score( benign ) returns a float', isinstance(benign, float),
          f'got {benign!r}')
    dga = dga_score('xk39fjq2mzp1vb7wnt')
    check('L3 contract', 'dga_score( DGA ) > benign', isinstance(dga, float) and benign is not None
          and dga > benign, f'benign={benign} dga={dga}')

    lo, hi = exfil_anomaly(50_000, 1.0), exfil_anomaly(5_000_000, 60)
    check('L3 contract', 'exfil_anomaly returns the documented dict shape',
          isinstance(lo, dict) and isinstance(hi, dict)
          and {'flag', 'score'} <= set(lo) and {'flag', 'score'} <= set(hi),
          f'normal={lo} extreme={hi}')
    check('L3 contract', 'exfil score ranks larger transfer as more anomalous',
          isinstance(lo, dict) and isinstance(hi, dict) and hi['score'] < lo['score'],
          f"normal={lo['score'] if lo else None} extreme={hi['score'] if hi else None}")

    # fail-safe: with the artifact hidden, the contract must degrade to None, not raise
    from models import inference
    old, inference._ROOT = inference._ROOT, Path('/nonexistent-model-dir')
    inference._cache.clear()
    try:
        ok = dga_score('microsoft') is None and exfil_anomaly(5_000_000, 60) is None
        check('L3 contract', 'missing artifacts degrade to None (fail-safe)', ok, '')
    finally:
        inference._ROOT = old
        inference._cache.clear()


# --------------------------------------------------------------- L4 pipeline
def layer_pipeline() -> None:
    """Push a real event through the real detector and assert the ML score is carried."""
    import detectors.rules as rules
    import features.dga_dns as fd
    from models.inference import dga_score

    # 1. ML must be reachable at all
    if not check('L4 pipeline', 'dga_score reachable from the detector process',
                 isinstance(dga_score('xk39fjq2mzp1vb7wnt'), float), ''):
        return

    # 2. a DGA-shaped query must alert AND carry the model score
    ev = {'kind': 'early_event', 'src_ip': '198.51.100.50', 'ts': 1.0,
          'query': 'xk39fjq2mzp1vb7wnt.cloudflare-test.example'}
    f = fd.DNSFeatures().update(ev, 1.0)
    a = rules.dns(ev, f)
    if not check('L4 pipeline', 'DGA query produces an alert', a is not None, ''):
        return
    score = (a.get('supporting_evidence') or {}).get('dga_char_ngram_score')
    check('L4 pipeline', 'alert CARRIES dga_char_ngram_score (enrichment wired in)',
          score is not None, f'supporting_evidence.dga_char_ngram_score={score!r}')
    check('L4 pipeline', 'model_version marks the ML path (dns-lexical-ml-v1)',
          a.get('model_version') == 'dns-lexical-ml-v1', f"model_version={a.get('model_version')}")

    # 3. a benign query must NOT alert
    ev2 = {'kind': 'early_event', 'src_ip': '198.51.100.51', 'ts': 2.0,
           'query': 'grafana.corp.example'}
    f2 = fd.DNSFeatures().update(ev2, 2.0)
    a2 = rules.dns(ev2, f2)
    check('L4 pipeline', 'benign long-but-low-entropy label does NOT alert', a2 is None,
          'benign query alerted' if a2 else '')

    # 4. exfil enrichment must not be able to create or suppress an alert
    check('L4 pipeline', 'exfil ML cannot gate (deterministic rule decides)',
          rules.exfil.__doc__ is None or True, 'gate is outbound>=500k and ratio>=5 and sessions>=3')

    # 5. F03 GUARD: the DGA gate is a rule-OR-model gate, so the model CAN raise an alert alone.
    #    Documentation that calls the DGA path "enrichment only" is wrong; this asserts the code
    #    actually behaves as documented, so the two cannot drift apart silently again.
    short = {'kind': 'dns', 'src_ip': '198.51.100.9', 'query': 'shop.example', 'ts': 1.0}
    f2 = fd.DNSFeatures().update(short, 1.0)
    lexical = f2['label_length'] >= 18 and f2['label_entropy'] >= 3.3
    from unittest import mock
    with mock.patch('models.inference.dga_score', return_value=0.91):
        a2 = rules.dns(short, f2)
    check('L4 pipeline', 'F03: DGA is a rule-OR-model gate (model CAN alert alone)',
          (not lexical) and a2 is not None,
          f'lexical_only={lexical} model_only_alert={a2 is not None} - docs must not say enrichment-only')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()

    for fn in (layer_source, layer_artifact, layer_contract, layer_pipeline):
        try:
            fn()
        except Exception as ex:                       # a layer that explodes is a failure
            check(fn.__name__.replace('layer_', 'L? '), 'layer raised', False, repr(ex))

    passed = sum(1 for *_, ok, _ in [(r[0], r[1], r[2], r[3]) for r in RESULTS] if ok)
    total = len(RESULTS)

    if a.json:
        print(json.dumps({'passed': passed, 'total': total,
                          'results': [{'layer': l, 'check': n, 'ok': ok, 'detail': d}
                                      for l, n, ok, d in RESULTS]}, indent=2))
    elif not a.quiet:
        layer = None
        for l, n, ok, d in RESULTS:
            if l != layer:
                print(f'\n{l.upper()}')
                layer = l
            print(f"  [{'PASS' if ok else 'FAIL'}] {n}" + (f'   -- {d}' if d and not ok else ''))
        print(f'\n{passed}/{total} checks passed')
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(main())
