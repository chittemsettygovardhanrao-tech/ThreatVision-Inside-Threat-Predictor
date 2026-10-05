"""Defensive risk fusion model."""

from __future__ import annotations
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from threatvision.core.models import RiskLevel


class RiskPredictor:
    """Combine anomaly and supervised probabilities into a 0-100 score."""

    def __init__(self) -> None:
        self.model = RandomForestClassifier(
            n_estimators=200, random_state=42, class_weight="balanced"
        )

    def fit(self, X, y) -> "RiskPredictor":
        self.model.fit(X, y)
        return self

    def predict(self, X, anomaly_scores) -> np.ndarray:
        probability = self.model.predict_proba(X)[:, -1]
        return np.clip((.4 * anomaly_scores + .6 * probability) * 100, 0, 100)

    @staticmethod
    def level(score: float) -> RiskLevel:
        if score >= 90:
            return RiskLevel.CRITICAL
        if score >= 75:
            return RiskLevel.HIGH
        if score >= 50:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
