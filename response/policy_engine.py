"""Simulation-first response policy engine."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml


@dataclass(frozen=True)
class Policy:
    name: str
    risk_gte: float
    actions: tuple[str, ...]


class PolicyEngine:
    """Evaluate YAML policies without executing response actions."""

    def __init__(self, path: str | Path = "config/policies.yaml") -> None:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        self.policies = []
        for item in data.get("policies", []):
            if item.get("enabled", True):
                self.policies.append(
                    Policy(
                        item["name"],
                        float(item["condition"]["risk_gte"]),
                        tuple(item.get("actions", [])),
                    )
                )

    def evaluate(self, risk_score: float) -> list[str]:
        actions = []
        for policy in self.policies:
            if risk_score >= policy.risk_gte:
                actions.extend(policy.actions)
        return sorted(set(actions))
