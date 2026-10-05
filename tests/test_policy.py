from threatvision.response.policy_engine import PolicyEngine


def test_policy_engine():
    engine = PolicyEngine("config/policies.yaml")
    assert "raise_alert" in engine.evaluate(80)
    assert "require_reauthentication" in engine.evaluate(95)
