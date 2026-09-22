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
def main():
 random.seed(26145); benign=['google','microsoft','cloudflare','ntro','service','updates','portal','intranet']; dga=[''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=18)) for _ in range(250)]
 texts=benign*40+dga; labels=[0]*(len(benign)*40)+[1]*len(dga)
 dga_model=Pipeline([('chars',TfidfVectorizer(analyzer='char',ngram_range=(2,5),min_df=1)),('classifier',LogisticRegression(max_iter=500,class_weight='balanced',random_state=26145))]);dga_model.fit(texts,labels);dump(dga_model,OUT/'dga_char_ngrams.joblib')
 # normal upload envelope spans routine..moderate volume so the exfil score DISCRIMINATES
 # inside the detector's operating region (alerts start at 5e5 bytes / ratio 5), not just
 # flags everything. Synthetic lab values — replace with real per-network baselines.
 normal=[[random.uniform(1e3,1e6),random.uniform(.2,8)] for _ in range(300)]; exfil=IsolationForest(contamination=.05,random_state=26145).fit(normal);dump(exfil,OUT/'exfil_baseline.joblib')
 import sklearn
 manifest={'training':'generated, labelled lab feature examples only','models':['dga_char_ngrams.joblib','exfil_baseline.joblib'],'seed':26145,'scikit_learn_version':sklearn.__version__,'warning':'No public-dataset performance is claimed.'};(OUT/'training_manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest))
if __name__=='__main__':main()
