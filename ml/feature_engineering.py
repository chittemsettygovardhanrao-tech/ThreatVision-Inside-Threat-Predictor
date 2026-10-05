"""UEBA feature engineering."""

from __future__ import annotations
from collections import defaultdict
import pandas as pd
from threatvision.core.models import ActivityEvent


FEATURES = [
    "off_hours_logins", "failed_logins", "file_access_volume",
    "sensitive_file_access", "usb_transfer_mb", "upload_mb",
    "privilege_changes",
]


def events_to_frame(events: list[ActivityEvent]) -> pd.DataFrame:
    """Convert normalized activity events into per-user feature rows."""
    rows = []
    for event in events:
        row = {
            "user_id": event.user_id,
            "timestamp": event.timestamp,
            "off_hours_logins": 0,
            "failed_logins": 0,
            "file_access_volume": 0,
            "sensitive_file_access": 0,
            "usb_transfer_mb": 0,
            "upload_mb": 0,
            "privilege_changes": 0,
        }
        a = event.attributes
        if event.event_type.value == "login":
            row["off_hours_logins"] = int(a.get("off_hours", False))
            row["failed_logins"] = int(a.get("failed_attempts", 0))
        elif event.event_type.value == "file_access":
            row["file_access_volume"] = int(a.get("file_count", 0))
            row["sensitive_file_access"] = int(a.get("sensitive_file", False))
        elif event.event_type.value == "usb":
            row["usb_transfer_mb"] = float(a.get("transfer_mb", 0))
        elif event.event_type.value == "network":
            row["upload_mb"] = float(a.get("upload_mb", 0))
        elif event.event_type.value == "privilege_change":
            row["privilege_changes"] = int(a.get("changed", False))
        rows.append(row)

    if not rows:
        return pd.DataFrame(columns=["user_id", "timestamp", *FEATURES])

    frame = pd.DataFrame(rows)
    return frame.groupby("user_id", as_index=False)[FEATURES].sum().merge(
        frame.groupby("user_id", as_index=False)["timestamp"].max(),
        on="user_id",
    )
