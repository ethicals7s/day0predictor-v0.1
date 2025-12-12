from __future__ import annotations

from pathlib import Path
import pandas as pd

from day0predict.model import load_model, predict_proba

def main():
    ds = Path("data/dataset.csv")
    if not ds.exists():
        raise SystemExit("Missing data/dataset.csv. Run: python scripts/build_dataset.py")

    model_path = Path("models/day0predict.joblib")
    if not model_path.exists():
        raise SystemExit("Missing model. Run: python scripts/train.py")

    df = pd.read_csv(ds)
    model = load_model(str(model_path))

    X = df.drop(columns=["label", "cve_id"]).to_dict(orient="records")
    y = df["label"].astype(int).tolist()

    probs = [predict_proba(model, r) for r in X]

    for k in [25, 50, 100]:
        top = sorted(range(len(probs)), key=lambda i: probs[i], reverse=True)[: min(k, len(probs))]
        prec = sum(y[i] for i in top) / max(1, len(top))
        print(f"precision@{k}: {prec:.3f}")

if __name__ == "__main__":
    main()
