"""ThreatVision domain models."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EventType(str, Enum):
    LOGIN = "login"
    FILE_ACCESS = "file_access"
    USB = "usb"
    NETWORK = "network"
    PRIVILEGE_CHANGE = "privilege_change"
    COMMUNICATION = "communication"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class ActivityEvent:
    user_id: str
    event_type: EventType
    timestamp: datetime
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"


@dataclass(slots=True)
class RiskAssessment:
    user_id: str
    timestamp: datetime
    risk_score: float
    risk_level: RiskLevel
    anomaly_score: float
    escalation_probability: float
    factors: list[dict[str, Any]] = field(default_factory=list)
