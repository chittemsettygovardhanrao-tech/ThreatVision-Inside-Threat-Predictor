from threatvision.ml.risk_predictor import RiskPredictor
from threatvision.core.models import RiskLevel


def test_risk_levels():
    assert RiskPredictor.level(10) is RiskLevel.LOW
    assert RiskPredictor.level(60) is RiskLevel.MEDIUM
    assert RiskPredictor.level(80) is RiskLevel.HIGH
    assert RiskPredictor.level(95) is RiskLevel.CRITICAL
