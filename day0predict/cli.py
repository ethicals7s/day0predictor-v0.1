from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from day0predict.features import featurize_cve, to_feature_dict
from day0predict.model import load_model
from day0predict.scoring import score_with_reasons

DEFAULT_MODEL = "models/day0predict.joblib"


# ----------------------------
# EPSS lookup (for score-epss)
# ----------------------------
def lookup_epss_features(cve_id: str, epss_csv: str = "data/epss.csv") -> dict[str, float]:
    p = Path(epss_csv)
    if not p.exists():
        raise FileNotFoundError(f"Missing {epss_csv}. Run: python scripts/fetch_nvd.py")

    df = pd.read_csv(p, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]

    # normalize possible variants
    if "epss_score" in df.columns and "epss" not in df.columns:
        df = df.rename(columns={"epss_score": "epss"})
    if "epss_percentile" in df.columns and "percentile" not in df.columns:
        df = df.rename(columns={"epss_percentile": "percentile"})
    if "cve_id" in df.columns and "cve" not in df.columns:
        df = df.rename(columns={"cve_id": "cve"})

    if "cve" not in df.columns or "epss" not in df.columns:
        raise ValueError(f"{epss_csv} missing required columns. Found: {list(df.columns)}")

    # match row
    cve_id = cve_id.strip()
    row = df[df["cve"].astype(str).str.strip() == cve_id]
    if row.empty:
        raise ValueError(f"{cve_id} not found in {epss_csv}")

    epss = float(row.iloc[0]["epss"])
    pct = float(row.iloc[0].get("percentile", 0.0))

    return {
        "epss": epss,
        "percentile": pct,
        "epss_ge_001": 1.0 if epss >= 0.01 else 0.0,
        "epss_ge_010": 1.0 if epss >= 0.10 else 0.0,
        "epss_ge_050": 1.0 if epss >= 0.50 else 0.0,
    }


# ------------------------------------
# Heuristic fallback (for score mode)
# ------------------------------------
def heuristic_score(features: dict[str, float]) -> tuple[int, list[dict]]:
    base = float(features.get("base_score", 0.0))
    risk = int(round(max(0.0, min(10.0, base)) * 10))  # 0-10 -> 0-100

    boosts = [
        ("attack_vector_network", 10),
        ("attack_complexity_low", 10),
        ("privileges_required_none", 10),
        ("user_interaction_none", 10),
        ("keyword_rce", 10),
        ("keyword_auth_bypass", 7),
        ("keyword_deser", 7),
        ("keyword_ssrf", 7),
        ("keyword_sqli", 5),
        ("scope_changed", 5),
    ]

    reasons = [{"feature": "base_score", "direction": "up", "weight": base}]
    for feat, bump in boosts:
        if features.get(feat, 0.0) >= 1.0:
            risk += bump
            reasons.append({"feature": feat, "direction": "up", "weight": float(bump)})

    risk = max(0, min(100, risk))
    return risk, reasons[:6]


# ----------------------------
# score: CVE JSON -> features
# ----------------------------
def cmd_score(args: argparse.Namespace) -> int:
    model_path = args.model or DEFAULT_MODEL

    # BOM-safe read on Windows
    cve = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))

    row = featurize_cve(cve)
    feats = to_feature_dict(row)

    # if no model, use heuristic
    if not Path(model_path).exists():
        risk, reasons = heuristic_score(feats)
        out = {
            "cve_id": row.cve_id,
            "risk": risk,
            "mode": "heuristic_fallback",
            "features": feats,
            "reasons": reasons,
            "disclaimer": "Defensive risk scoring only. No trained model found; using heuristic fallback.",
        }
        print(json.dumps(out, indent=2) if args.format == "json" else out)
        return 0

    # trained model (may not align with CVSS features; kept for backward-compat)
    model = load_model(model_path)
    risk, reasons_obj = score_with_reasons(model, feats)

    out = {
        "cve_id": row.cve_id,
        "risk": risk,
        "mode": "trained_model",
        "features": feats,
        "reasons": [r.__dict__ for r in reasons_obj],
        "disclaimer": "Defensive risk scoring only.",
    }
    print(json.dumps(out, indent=2) if args.format == "json" else out)
    return 0


# -----------------------------------------
# score-epss: CVE ID -> EPSS -> trained model
# -----------------------------------------
def cmd_score_epss(args: argparse.Namespace) -> int:
    model_path = args.model or DEFAULT_MODEL
    if not Path(model_path).exists():
        raise SystemExit(f"Missing trained model: {model_path}")

    feats = lookup_epss_features(args.cve_id, epss_csv=args.epss_csv)

    model = load_model(model_path)
    risk, reasons_obj = score_with_reasons(model, feats)

    out = {
        "cve_id": args.cve_id,
        "risk": risk,
        "mode": "trained_model_epss",
        "features": feats,
        "reasons": [r.__dict__ for r in reasons_obj],
        "disclaimer": "Defensive risk scoring only. Uses EPSS-derived features.",
    }
    print(json.dumps(out, indent=2) if args.format == "json" else out)
    return 0


def cmd_train_hint(_: argparse.Namespace) -> int:
    print("Training is done via scripts/train.py (see README).")
    return 0


def main() -> None:
    p = argparse.ArgumentParser(
        prog="day0predict",
        description="Early exploitation risk scoring (defensive).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("score", help="Score a CVE JSON file")
    s.add_argument("--file", required=True, help="Path to CVE JSON file")
    s.add_argument("--model", default=DEFAULT_MODEL, help="Path to trained model artifact")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.set_defaults(func=cmd_score)

    e = sub.add_parser("score-epss", help="Score by CVE ID using EPSS (recommended)")
    e.add_argument("--cve-id", required=True, help="CVE identifier, e.g., CVE-2021-44228")
    e.add_argument("--epss-csv", default="data/epss.csv", help="Path to EPSS CSV")
    e.add_argument("--model", default=DEFAULT_MODEL, help="Path to trained model artifact")
    e.add_argument("--format", choices=["text", "json"], default="text")
    e.set_defaults(func=cmd_score_epss)

    t = sub.add_parser("train", help="Show training instructions")
    t.set_defaults(func=cmd_train_hint)

    args = p.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
