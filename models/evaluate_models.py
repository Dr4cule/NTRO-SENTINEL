#!/usr/bin/env python3
"""Evaluate the starter DGA classifier on a disjoint generated-lab holdout set."""
from __future__ import annotations
import json, os, random
from pathlib import Path
from joblib import load
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

OUT=Path(os.getenv('MODEL_DIR','models/artifacts'))
def main():
 random.seed(26146)
 benign=['google','microsoft','cloudflare','ntro','service','updates','portal','intranet']*15
 dga=[''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=18)) for _ in range(120)]
 labels=[0]*len(benign)+[1]*len(dga); model=load(OUT/'dga_char_ngrams.joblib'); predicted=model.predict(benign+dga)
 precision,recall,f1,_=precision_recall_fscore_support(labels,predicted,average='binary',zero_division=0)
 result={'model':'dga_char_ngrams.joblib','evaluation_data':'disjoint generated lab lexical holdout (seed 26146); not public traffic','split':'training seed 26145, evaluation seed 26146','samples':len(labels),'positive_samples':sum(labels),'metrics':{'precision':precision,'recall':recall,'f1':f1},'confusion_matrix_labels':['benign_like','dga_like'],'confusion_matrix':confusion_matrix(labels,predicted).tolist(),'limitation':'This is reproducibility evidence for the starter model only; it must not be presented as real-world DGA performance.'}
 (OUT/'dga_holdout_evaluation.json').write_text(json.dumps(result,indent=2)); print(json.dumps(result,indent=2))
if __name__=='__main__':main()
