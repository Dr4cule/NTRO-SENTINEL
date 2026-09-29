#!/usr/bin/env python3
"""Reproducibly train compact, explainable prototype models on generated lab labels.
These models are not claimed as general malware classifiers; replace the input with
documented public/lab datasets before publishing any model metric.
"""
from __future__ import annotations
import json, os, random
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from joblib import dump

OUT=Path(os.getenv('MODEL_DIR','models/artifacts'));OUT.mkdir(parents=True,exist_ok=True)
# F-06: the training benign vocabulary and the EVALUATION benign vocabulary must be DISJOINT,
# otherwise the reported F1 is a self-test (the model is scored on the exact words it memorised).
# models/holdout.py owns both lists so the split is auditable in one place.
from models.holdout import TRAIN_BENIGN, DGA_ALPHABET, DGA_LENGTHS

def main():
 random.seed(26145)
 benign=list(TRAIN_BENIGN)
 # DGA-like labels now span several lengths (not just 18 chars) so the classifier cannot key on
 # a single token length, matching the varied-length holdout in models/holdout.py.
 dga=[''.join(random.choices(DGA_ALPHABET,k=random.choice(DGA_LENGTHS))) for _ in range(250)]
 texts=benign*40+dga; labels=[0]*(len(benign)*40)+[1]*len(dga)
 dga_model=Pipeline([('chars',TfidfVectorizer(analyzer='char',ngram_range=(2,5),min_df=1)),('classifier',LogisticRegression(max_iter=500,class_weight='balanced',random_state=26145))]);dga_model.fit(texts,labels);dump(dga_model,OUT/'dga_char_ngrams.joblib')
 # normal upload envelope spans routine..moderate volume so the exfil score DISCRIMINATES
 # inside the detector's operating region (alerts start at 5e5 bytes / ratio 5), not just
 # flags everything. Synthetic lab values — replace with real per-network baselines.
 normal=[[random.uniform(1e3,1e6),random.uniform(.2,8)] for _ in range(300)]; exfil=IsolationForest(contamination=.05,random_state=26145).fit(normal);dump(exfil,OUT/'exfil_baseline.joblib')
 import hashlib, sklearn
 def sha256(p):
  h=hashlib.sha256()
  with open(p,'rb') as f:
   for chunk in iter(lambda: f.read(1<<20), b''): h.update(chunk)
  return h.hexdigest()
 # SHA-256 sidecars: models/inference.py refuses to unpickle an artifact whose digest does not
 # match, so anything able to write MODEL_DIR can no longer smuggle code into the detectors.
 digests={name: sha256(OUT/name) for name in ('dga_char_ngrams.joblib','exfil_baseline.joblib')}
 manifest={'training':'generated, labelled lab feature examples only','models':['dga_char_ngrams.joblib','exfil_baseline.joblib'],'seed':26145,'scikit_learn_version':sklearn.__version__,'sha256':digests,'warning':'No public-dataset performance is claimed.'};(OUT/'training_manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest))
if __name__=='__main__':main()
