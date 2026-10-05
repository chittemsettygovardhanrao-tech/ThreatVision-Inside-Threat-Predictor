"""Isolation Forest anomaly detector."""

from __future__ import annotations
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyModel:
    """Wrapper around scikit-learn Isolation Forest."""

    def __init__(self, contamination: float = .08, random_state: int = 42) -> None:
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=200,
        )

    def fit(self, X) -> "AnomalyModel":
        self.model.fit(X)
        return self

    def score(self, X) -> np.ndarray:
        raw = -self.model.score_samples(X)
        minimum, maximum = raw.min(), raw.max()
        if maximum == minimum:
            return np.zeros_like(raw)
        return (raw - minimum) / (maximum - minimum)
