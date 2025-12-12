from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from day0predict.model import train, save, predict_proba


def main():
    ds = Path("data/dataset.csv")
    if not ds.exists():
        raise SystemExit("Missing data/dataset.csv. Run: python scripts/build_dataset.py")

    df = pd.read_csv(ds)
    y = df["label"].astype(int).tolist()
    X = df.drop(columns=["label", "cve_id"]).to_dict(orient="records")

    # Guard: need at least 2 classes
    classes = sorted(set(y))
    if len(classes) < 2:
        print("WARNING: Dataset contains only one class.")
        print("Labels found:", classes)
        print("Training skipped. Pipeline is working correctly.")
        return

    # Guard: stratified split needs enough samples
    pos = sum(1 for v in y if v == 1)
    neg = sum(1 for v in y if v == 0)
    stratify = y if min(pos, neg) >= 2 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=stratify
    )

    model = train(X_train, y_train)

    probs = [predict_proba(model, r) for r in X_test]
    preds = [1 if p >= 0.5 else 0 for p in probs]

    print(classification_report(y_test, preds, digits=3))
    try:
        print("ROC-AUC:", roc_auc_score(y_test, probs))
    except Exception:
        pass

    Path("models").mkdir(exist_ok=True)
    out = "models/day0predict.joblib"
    save(model, out)
    print("Saved", out)


if __name__ == "__main__":
    main()
