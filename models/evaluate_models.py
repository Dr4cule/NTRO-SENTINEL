#!/usr/bin/env python3
"""Evaluate the starter DGA classifier on a DISJOINT generated-lab holdout.

F-06 fix (2026-09-29): the benign vocabulary here is now disjoint from the training vocabulary
(`models/holdout.py`), and the DGA class spans several lengths instead of only 18 characters.
The previous version evaluated on the same eight words the model was trained on, so its
precision/recall/F1 = 1.0 was a self-test.

A disjoint split normally LOWERS the reported F1. That is not a regression — it is the first
number in this repo that means anything. If this script ever reports a perfect score again,
check that the split is still disjoint before believing it.

The result remains a REPRODUCIBILITY measurement on generated labels. It is not real-world DGA
performance, and `limitation` in the emitted JSON says exactly that.
"""
from __future__ import annotations
import json, os, random
from pathlib import Path
from joblib import load
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from models.holdout import EVAL_BENIGN, DGA_ALPHABET, DGA_LENGTHS

OUT = Path(os.getenv('MODEL_DIR', 'models/artifacts'))


def build_holdout(seed=26146, n_dga=120, repeats=15):
    """Disjoint-by-construction holdout: held-out benign words + freshly generated DGA labels."""
    rng = random.Random(seed)
    benign = list(EVAL_BENIGN) * repeats
    dga = [''.join(rng.choices(DGA_ALPHABET, k=rng.choice(DGA_LENGTHS))) for _ in range(n_dga)]
    return benign + dga, [0] * len(benign) + [1] * len(dga)


def main():
    model = load(OUT / 'dga_char_ngrams.joblib')
    texts, labels = build_holdout()
    predicted = model.predict(texts)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted, average='binary', zero_division=0)
    result = {
        'model': 'dga_char_ngrams.joblib',
        'evaluation_data': 'generated lab lexical holdout on a benign vocabulary DISJOINT from '
                           'training; not public traffic',
        'split': 'training seed 26145, evaluation seed 26146, disjoint benign vocabularies '
                 '(models/holdout.py), DGA lengths varied 12-27',
        'benign_vocabulary_disjoint_from_training': True,
        'samples': len(labels),
        'positive_samples': sum(labels),
        'metrics': {'precision': precision, 'recall': recall, 'f1': f1},
        'confusion_matrix_labels': ['benign_like', 'dga_like'],
        'confusion_matrix': confusion_matrix(labels, predicted).tolist(),
        'limitation': 'Reproducibility evidence for the starter model on GENERATED labels with a '
                      'disjoint vocabulary. It must not be presented as real-world DGA accuracy; '
                      'a real claim needs documented, family-separated public/lab data.',
    }
    (OUT / 'dga_holdout_evaluation.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
