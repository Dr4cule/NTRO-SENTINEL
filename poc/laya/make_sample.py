#!/usr/bin/env python3
"""Build the shared, deterministic train/test split used by BOTH the baseline
and Laya, so the comparison is apples-to-apples. Stratified, disjoint, SEED=42.

Laya is zero-shot (ignores the train split); the baseline trains on it. The test
split is what both are scored on. Pickles land in poc/laya/data/.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C


def main(test_per=500, train_per=4000):
    os.makedirs(C.DATA, exist_ok=True)
    df = C.load_selected(C.BROAD)
    test = df.groupby("y", group_keys=False).sample(n=test_per, random_state=C.SEED)
    rest = df.drop(test.index)
    train = rest.groupby("y", group_keys=False).sample(n=train_per, random_state=C.SEED)
    test.to_pickle(os.path.join(C.DATA, "test.pkl"))
    train.to_pickle(os.path.join(C.DATA, "train.pkl"))
    overlap = len(set(train["event_id"]) & set(test["event_id"]))
    print("train:", train["y"].value_counts().to_dict(),
          "| test:", test["y"].value_counts().to_dict(),
          "| train/test event overlap:", overlap)
    assert overlap == 0, "train and test must be disjoint"


if __name__ == "__main__":
    a = sys.argv
    main(int(a[1]) if len(a) > 1 else 500, int(a[2]) if len(a) > 2 else 4000)
