import numpy as np
from sklearn.linear_model import LogisticRegression

from day0predict.model import TrainedModel, FEATURE_ORDER
from day0predict.scoring import score_with_reasons

def test_score_with_reasons_runs():
    # Create a tiny fake trained model
    clf = LogisticRegression()
    clf.classes_ = np.array([0, 1])
    clf.coef_ = np.zeros((1, len(FEATURE_ORDER)))
    clf.intercept_ = np.array([0.0])

    # Give base_score positive influence so we get a reason
    clf.coef_[0, FEATURE_ORDER.index("base_score")] = 1.0

    def predict_proba(X):
        p = np.clip(X[:, FEATURE_ORDER.index("base_score")] / 10.0, 0, 1)
        return np.vstack([1 - p, p]).T

    clf.predict_proba = predict_proba  # monkey-patch for test

    model = TrainedModel(clf=clf)

    risk, reasons = score_with_reasons(model, {"base_score": 9.0})
    assert 80 <= risk <= 100
    assert any(r.feature == "base_score" for r in reasons)
