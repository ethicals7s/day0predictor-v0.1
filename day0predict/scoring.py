from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from day0predict.model import FEATURE_ORDER, TrainedModel, predict_proba

@dataclass(frozen=True)
class Reason:
    feature: str
    direction: str  # "up" / "down"
    weight: float

def score_with_reasons(model: TrainedModel, features: Dict[str, float]) -> Tuple[int, List[Reason]]:
    """
    Returns (risk_score_0_100, reasons).
    Reasons are derived from linear model coefficients * feature value (simple + transparent).
    """
    p = predict_proba(model, features)
    risk = int(round(p * 100))

    coef = model.clf.coef_[0]  # sklearn linear model coefficients
    contribs: List[Tuple[str, float]] = []
    for i, f in enumerate(FEATURE_ORDER):
        contribs.append((f, float(coef[i]) * float(features.get(f, 0.0))))

    contribs.sort(key=lambda x: abs(x[1]), reverse=True)

    reasons: List[Reason] = []
    for f, c in contribs[:6]:
        if c == 0:
            continue
        reasons.append(
            Reason(
                feature=f,
                direction="up" if c > 0 else "down",
                weight=abs(c),
            )
        )
    return risk, reasons
