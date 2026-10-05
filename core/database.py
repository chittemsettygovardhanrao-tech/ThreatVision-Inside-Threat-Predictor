"""SQLite persistence."""

from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from .models import ActivityEvent, RiskAssessment


class Database:
    """SQLite database using one connection per operation."""

    def __init__(self, path: str | Path = "data/threatvision.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self) -> None:
        with self.connection() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS activity_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                attributes_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_activity_user_time
                ON activity_events(user_id, timestamp);

            CREATE TABLE IF NOT EXISTS risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                escalation_probability REAL NOT NULL,
                factors_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                mode TEXT NOT NULL,
                approved INTEGER NOT NULL,
                metadata_json TEXT NOT NULL,
                digest TEXT NOT NULL,
                previous_digest TEXT NOT NULL
            );
            """)

    def insert_activity(self, event: ActivityEvent) -> None:
        with self.connection() as db:
            db.execute(
                """INSERT INTO activity_events
                (user_id,event_type,timestamp,source,attributes_json)
                VALUES (?,?,?,?,?)""",
                (
                    event.user_id, event.event_type.value,
                    event.timestamp.isoformat(), event.source,
                    json.dumps(event.attributes, default=str),
                ),
            )

    def insert_risk(self, assessment: RiskAssessment) -> None:
        with self.connection() as db:
            db.execute(
                """INSERT INTO risk_assessments
                (user_id,timestamp,risk_score,risk_level,anomaly_score,
                 escalation_probability,factors_json)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    assessment.user_id, assessment.timestamp.isoformat(),
                    assessment.risk_score, assessment.risk_level.value,
                    assessment.anomaly_score, assessment.escalation_probability,
                    json.dumps(assessment.factors),
                ),
            )

    def recent_activity(self, limit: int = 100):
        limit = max(1, min(int(limit), 10_000))
        with self.connection() as db:
            return db.execute(
                f"SELECT * FROM activity_events ORDER BY timestamp DESC LIMIT {limit}"
            ).fetchall()
