from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import numpy as np
from joblib import dump, load
from sklearn.linear_model import LogisticRegression

FEATURE_ORDER = [
    "epss",
    "percentile",
    "epss_ge_001",
    "epss_ge_010",
    "epss_ge_050",
]


@dataclass
class TrainedModel:
    clf: LogisticRegression

def _matrix(rows: List[Dict[str, float]]) -> np.ndarray:
    X = np.zeros((len(rows), len(FEATURE_ORDER)), dtype=float)
    for i, r in enumerate(rows):
        for j, f in enumerate(FEATURE_ORDER):
            X[i, j] = float(r.get(f, 0.0))
    return X

def train(rows: List[Dict[str, float]], y: List[int]) -> TrainedModel:
    X = _matrix(rows)
    y_arr = np.array(y, dtype=int)
    clf = LogisticRegression(max_iter=500, class_weight="balanced")
    clf.fit(X, y_arr)
    return TrainedModel(clf=clf)

def predict_proba(model: TrainedModel, row: Dict[str, float]) -> float:
    X = _matrix([row])
    p = model.clf.predict_proba(X)[0, 1]
    return float(p)

def save(model: TrainedModel, path: str) -> None:
    dump({"clf": model.clf}, path)

def load_model(path: str) -> TrainedModel:
    obj = load(path)
    return TrainedModel(clf=obj["clf"])
