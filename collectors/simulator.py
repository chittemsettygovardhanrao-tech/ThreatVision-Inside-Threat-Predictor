"""Synthetic defensive UEBA event generator."""

from __future__ import annotations
import random
import threading
from datetime import datetime, timedelta, timezone
from . import __name__ as _package_marker  # keeps package import explicit
from threatvision.core.models import ActivityEvent, EventType
from threatvision.core.event_bus import EventBus
from threatvision.core.database import Database


class SyntheticDataGenerator:
    """Generate synthetic normal and anomalous activity without touching real systems."""

    def __init__(self, event_bus: EventBus, database: Database, interval_seconds: float = 1.0) -> None:
        self.event_bus = event_bus
        self.database = database
        self.interval_seconds = max(0.1, interval_seconds)
        self.users = ["alice", "bob", "charlie", "diana", "eve", "frank", "grace", "heidi"]
        self.anomalous_user = "heidi"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.random = random.Random(42)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="SyntheticCollector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def generate_batch(self, count: int = 1000) -> list[ActivityEvent]:
        now = datetime.now(timezone.utc)
        events = []
        for _ in range(max(0, count)):
            user = self.random.choice(self.users)
            anomalous = user == self.anomalous_user
            timestamp = now - timedelta(seconds=self.random.randint(0, 72 * 3600))
            event = self._event(user, timestamp, anomalous)
            self.database.insert_activity(event)
            events.append(event)
        return events

    def _run(self) -> None:
        while not self._stop.is_set():
            now = datetime.now(timezone.utc)
            user = self.random.choice(self.users)
            event = self._event(user, now, user == self.anomalous_user)
            self.database.insert_activity(event)
            self.event_bus.publish("activity", event)
            self._stop.wait(self.interval_seconds)

    def _event(self, user: str, timestamp: datetime, anomalous: bool) -> ActivityEvent:
        event_type = self.random.choice(list(EventType)[:5])
        if event_type is EventType.LOGIN:
            return ActivityEvent(
                user, event_type, timestamp,
                {"failed_attempts": self.random.randint(1, 6) if anomalous else self.random.choice([0, 0, 0, 1]),
                 "off_hours": (timestamp.hour < 7 or timestamp.hour >= 21) or anomalous},
                "synthetic",
            )
        if event_type is EventType.FILE_ACCESS:
            return ActivityEvent(
                user, event_type, timestamp,
                {"file_count": self.random.randint(100, 500) if anomalous else self.random.randint(1, 40),
                 "sensitive_file": anomalous and self.random.random() < .8,
                 "write_bytes": self.random.randint(100_000_000, 2_000_000_000) if anomalous else self.random.randint(1_000, 10_000_000)},
                "synthetic",
            )
        if event_type is EventType.USB:
            return ActivityEvent(
                user, event_type, timestamp,
                {"transfer_mb": self.random.randint(100, 2000) if anomalous else self.random.randint(1, 50)},
                "synthetic",
            )
        if event_type is EventType.NETWORK:
            return ActivityEvent(
                user, event_type, timestamp,
                {"upload_mb": self.random.randint(500, 5000) if anomalous else self.random.randint(1, 100),
                 "external": anomalous},
                "synthetic",
            )
        return ActivityEvent(
            user, event_type, timestamp,
            {"changed": anomalous and self.random.random() < .6},
            "synthetic",
        )
