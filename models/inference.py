"""Optional ML enrichment for the detectors. Every call degrades to None when the
artifact is missing, failed its integrity check, or was pickled under a different
scikit-learn (version gate = pickle safety); the caller then falls back to its
deterministic rule. Set MODEL_DIR to point at a different artifact directory (matches
models/train_models.py)."""
from pathlib import Path
import hashlib
import json
import os

_ROOT = Path(os.getenv('MODEL_DIR', 'models/artifacts'))
_cache = {}


def _sha256(path):
    """Streamed digest so a large artifact is never held in memory."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _verified(filename):
    """Return the artifact path only if its SHA-256 matches the manifest sidecar.

    joblib artifacts are pickles: loading one executes its contents, so anything that can
    write MODEL_DIR is arbitrary code execution. The manifest pins an expected digest, so a
    swapped or tampered artifact is refused before it is ever unpickled. A missing digest
    (e.g. artifacts from an older train_models) also fails closed.
    """
    path = _ROOT / filename
    manifest_path = _ROOT / 'training_manifest.json'
    if not path.is_file() or not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text())
        expected = (manifest.get('sha256') or {}).get(filename)
        if not expected:
            return None
        return path if _sha256(path) == expected else None
    except Exception:
        return None


def _load(filename):
    """Load a joblib model once, but only if the digest AND the pickle's sklearn match ours."""
    if filename not in _cache:
        try:
            import sklearn
            manifest = json.loads((_ROOT / 'training_manifest.json').read_text())
            if manifest.get('scikit_learn_version') != sklearn.__version__: return None
            path = _verified(filename)
            if path is None: return None
            from joblib import load
            _cache[filename] = load(path)
        except Exception: return None
    return _cache.get(filename)

def dga_score(label):
 """P(DGA) for a DNS label, or None if the char-ngram model is unavailable."""
 m = _load('dga_char_ngrams.joblib')
 try: return float(m.predict_proba([label])[0][1]) if m is not None else None
 except Exception: return None

def exfil_anomaly(outbound_bytes, ratio):
 """Second-opinion IsolationForest over [outbound_bytes, out/in ratio]. ENRICHMENT
 ONLY — never the alert gate. Returns {'flag': bool, 'score': float} where a lower
 score means more anomalous vs the lab baseline envelope, or None if unavailable."""
 m = _load('exfil_baseline.joblib')
 if m is None: return None
 try:
  x = [[float(outbound_bytes), float(ratio)]]
  return {'flag': int(m.predict(x)[0]) == -1, 'score': round(float(m.decision_function(x)[0]), 4)}
 except Exception: return None

if __name__ == '__main__':
 # runnable check: train tiny models under the CURRENT sklearn into a temp dir, then
 # prove enrichment runs, discriminates by magnitude, and degrades to None when absent.
 import subprocess, sys, tempfile
 with tempfile.TemporaryDirectory() as d:
  subprocess.run([sys.executable, '-m', 'models.train_models'], check=True,
                 env={**os.environ, 'MODEL_DIR': d}, capture_output=True)
  _ROOT = Path(d); _cache.clear()
  assert dga_score('microsoft') is not None, 'model should load under matching sklearn'
  assert dga_score('xk39fjq2mzp1vb7wnt') > dga_score('microsoft'), 'random label = higher DGA score'
  normal, extreme = exfil_anomaly(50_000, 1.0), exfil_anomaly(5_000_000, 60)
  assert normal and extreme, 'exfil model should load'
  assert extreme['flag'] and extreme['score'] < normal['score'], 'bigger exfil = more anomalous'
  _ROOT = Path(d) / 'absent'; _cache.clear()
  assert exfil_anomaly(5_000_000, 60) is None and dga_score('microsoft') is None, 'absent model -> None'
  print('inference self-check OK')
