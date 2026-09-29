"""Numeric features for the real-data DGA model.

Lives in its OWN importable module (not the training script) so the pickled
FunctionTransformer references models.numeric_feats.numeric_features — a path that
resolves at inference time. (Defining it in a script run via `python -m` pickles it
as __main__.<fn>, which makes the artifact unloadable outside that process.)
"""
from __future__ import annotations
import numpy as np
from math import log2


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def numeric_features(labels):
    """[label_length, shannon_entropy] per label — the two features the old synthetic
    model lacked, which is why it keyed on token length and flagged 'grafana'."""
    return np.array([[len(s), shannon(s)] for s in labels], dtype=float)