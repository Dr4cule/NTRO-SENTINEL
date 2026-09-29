"""Train/evaluate label sets for the DGA starter classifier — kept in ONE place so the split
is auditable.

WHY THIS FILE EXISTS (F-06, 2026-09-29)
---------------------------------------
`train_models.py` and `evaluate_models.py` previously both used the SAME eight benign words.
The classifier was therefore evaluated on the exact vocabulary it had memorised, and the
reported precision/recall/F1 = 1.0 was a self-test, not a measurement. The holdout has to be
disjoint in TWO dimensions, not just a different random seed:

  * **Vocabulary** — `EVAL_BENIGN` shares no label with `TRAIN_BENIGN`, so the model is scored
    on words it has never seen.
  * **Generative process** — both classes are still generated here, so this remains a
    *reproducibility* harness, not a real-world claim. `evaluate_models.py` says so in its
    output, and the docstring must not be quietly upgraded to "accurate DGA detection".

A disjoint split usually LOWERS the reported F1. That is the point: a number that survives a
harder split is evidence; a number that only survives a leaked one is decoration.

MEASURED OUTCOME (2026-09-29, sklearn 1.8.0)
--------------------------------------------
On this disjoint holdout the starter classifier scores **precision 0.32 / recall 1.00 /
F1 0.48**, versus the leaked-split 1.00 / 1.00 / 1.00 it reported before. Confusion matrix:
255 of 270 held-out benign labels are predicted DGA.

Diagnosis: the model learned **token length, not entropy**. Per-word probability rises with
length regardless of content — `grafana` (7 chars) 0.82, `sonarqube` (9) 0.84, while the
memorised training words score ~0.12. A char-ngram model over synthetic fixed-ish-length random
strings has no way to learn that, because nothing in the training data rewards it.

This is a REAL defect in the starter model and is deliberately left in place rather than
tuned away: the lexical gate in `detectors/rules.py` is the actual detector, the ML is
second-opinion enrichment, and the honest number is more useful than a flattering one. Fixing
it properly needs real labelled DGA families (dns-zen, DGArchive) with per-family splits —
which is exactly what the project docs already say must happen before any accuracy claim.
The committed evaluation artifact therefore reports 0.48, and `model_cards/README.md` records
this as a known limitation rather than a result.

TRAIN_BENIGN — ordinary short, low-entropy service labels (the easy case).
EVAL_BENIGN — deliberately harder: longer, hyphenated and camel-ish compound words, because
real benign labels are not all short dictionary tokens. If the model only ever saw 'google',
it has learned "short == benign" rather than "high entropy == DGA", and the holdout exposes
exactly that.
"""
from __future__ import annotations

# Deliberately disjoint from EVAL_BENIGN below. Verified by test_models_split.py.
TRAIN_BENIGN = (
    'google', 'microsoft', 'cloudflare', 'ntro', 'service', 'updates', 'portal', 'intranet',
    'mail', 'cdn', 'api', 'static', 'assets', 'login', 'auth', 'shop', 'news',
)

# HELD OUT. None of these appear in TRAIN_BENIGN.
EVAL_BENIGN = (
    'kubernetes', 'grafana', 'jenkins', 'docker-registry', 'artifactory', 'sonarqube',
    'elasticsearch', 'postgresql-primary', 'billing-invoices', 'warehouse-sync',
    'elasticsearch-head', 'keycloak-realm', 'prometheus-thanos', 'gitlab-runner',
    'openshift-console', 'cloudwatch-agent', 's3-object-store', 'vcenter-datastore',
)

# DGA-like generator alphabet. Kept explicit so both scripts draw from the same space.
DGA_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'

# DGA length distribution: pure 18-char strings is a trivially separable synthetic class. Real
# DGAs vary, so the holdout includes shorter and longer lengths to avoid reporting a number
# that only holds for one length.
DGA_LENGTHS = (12, 15, 18, 18, 22, 27)
