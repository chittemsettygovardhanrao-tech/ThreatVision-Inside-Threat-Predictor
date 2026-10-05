
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QThread,
    Qt,
    QUrl,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QPainter, QPixmap
from PyQt6.QtMultimedia import QAudioOutput, QMediaPlayer, QVideoSink
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QDialog,
    QDialogButtonBox,
    QPlainTextEdit,
    QScrollArea,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

APP_TITLE = "THREAT VISION"
EVENT_LIMIT = 1000
USB_ACTIVITY_LIMIT = 500
EVENT_POLL_SECONDS = 2.0
DEVICE_POLL_SECONDS = 5.0
MTP_POLL_SECONDS = 15.0
GUI_EVENT_REFRESH_MS = 350
VIDEO_MAX_FPS = 20.0

BASE_DIR = Path(__file__).resolve().parent
VIDEO_PATH = BASE_DIR / "assets" / "background.mp4"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
LOGGER = logging.getLogger("threatvision")

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

try:
    import win32com.client
    import pythoncom
except ImportError:
    win32com = None
    pythoncom = None


def text(value: Any) -> str:
    return "" if value is None else str(value)


def bytes_text(value: Any) -> str:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "N/A"
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for unit in units:
        if x < 1024 or unit == "TB":
            return f"{x:.1f} {unit}" if unit != "B" else f"{int(x)} B"
        x /= 1024
    return "N/A"


def ps_json(script: str, timeout: float = 6.0) -> Any:
    """Run a small read-only PowerShell query with a hard timeout."""
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        LOGGER.debug("PowerShell query failed: %s", exc)
        return None


def windows_devices() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Query WPD and removable disks in one fast PowerShell call.

    WPD detection deliberately matches Class='WPD' and Status='OK', so a
    device such as 'OPPO A59 5G' is detected even though its name contains
    neither 'Android' nor 'Phone'.
    """
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$wpd = @(Get-PnpDevice -PresentOnly |
    Where-Object { $_.Class -eq 'WPD' -and $_.Status -eq 'OK' } |
    Select-Object Status,Class,FriendlyName,InstanceId,Description)

$drives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" |
    Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace)

[pscustomobject]@{
    WPD = $wpd
    DRIVES = $drives
} | ConvertTo-Json -Compress -Depth 4
"""
    data = ps_json(script)
    if not isinstance(data, dict):
        return [], []

    wpd_raw = data.get("WPD", [])
    drives_raw = data.get("DRIVES", [])

    if isinstance(wpd_raw, dict):
        wpd_raw = [wpd_raw]
    if isinstance(drives_raw, dict):
        drives_raw = [drives_raw]

    devices = []
    for item in wpd_raw if isinstance(wpd_raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = text(item.get("FriendlyName")).strip()
        if name:
            devices.append(
                {
                    "name": name,
                    "status": text(item.get("Status")) or "OK",
                    "class": text(item.get("Class")) or "WPD",
                    "instance": text(item.get("InstanceId")),
                    "description": text(item.get("Description")),
                }
            )

    drives = []
    for item in drives_raw if isinstance(drives_raw, list) else []:
        if not isinstance(item, dict):
            continue
        drive = text(item.get("DeviceID"))
        if drive:
            drives.append(
                {
                    "drive": drive,
                    "label": text(item.get("VolumeName")) or "Removable",
                    "filesystem": text(item.get("FileSystem")) or "N/A",
                    "size": item.get("Size"),
                    "free": item.get("FreeSpace"),
                }
            )

    return devices, drives


ALERT_EVENT_IDS = {
    1102,  # Security audit log cleared
    4625,  # Failed account logon
    4740,  # Account locked out
    4720,  # User account created
    4726,  # User account deleted
    4697,  # Service installed
    7045,  # Service installed (System)
    4104,  # PowerShell script block logging
}

RISK_EVENT_WEIGHTS = {
    1102: 35,
    4625: 25,
    4740: 30,
    4720: 25,
    4726: 20,
    4697: 20,
    7045: 20,
    4104: 18,
    4672: 15,
    4688: 12,
    5140: 10,
    5145: 10,
}

RISK_KEYWORDS = {
    "failed": 10,
    "failure": 10,
    "denied": 10,
    "unauthorized": 14,
    "audit failure": 15,
    "logon failure": 15,
    "locked out": 15,
    "credential": 8,
    "powershell": 8,
    "script": 6,
    "service installed": 12,
    "malware": 20,
    "suspicious": 18,
    "tamper": 18,
    "cleared": 12,
}


def calculate_event_risk(item: dict[str, Any]) -> int:
    """Calculate a transparent 0-100 risk signal for one event.

    This is an investigative signal, not a claim that a user or event is
    malicious. It combines Windows event severity, selected event IDs and
    security-relevant message/source keywords.
    """
    level = text(item.get("level")).upper()
    event_id = int(item.get("event_id", 0) or 0)
    message = text(item.get("message")).lower()
    source = text(item.get("source")).lower()

    base = {
        "ERROR": 50,
        "WARNING": 30,
        "AUDIT FAILURE": 55,
        "AUDIT": 20,
        "AUDIT SUCCESS": 8,
        "INFO": 5,
    }.get(level, 10)

    score = base + RISK_EVENT_WEIGHTS.get(event_id, 0)

    combined = f"{message} {source}"
    for keyword, weight in RISK_KEYWORDS.items():
        if keyword in combined:
            score += weight

    return max(0, min(100, score))


def risk_band(score: int) -> str:
    """Return a human-readable band for the numeric risk signal."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "ELEVATED"
    if score >= 20:
        return "MODERATE"
    return "LOW"


def is_alert_event(item: dict[str, Any]) -> bool:
    """Return True when an event belongs in the analyst alert view."""
    level = text(item.get("level")).upper()
    event_id = int(item.get("event_id", 0) or 0)
    return (
        level in {"ERROR", "WARNING", "AUDIT FAILURE"}
        or event_id in ALERT_EVENT_IDS
        or int(item.get("risk", 0) or 0) >= 55
    )


def apply_contextual_risk(rows: list[dict[str, Any]]) -> None:
    """Add a small frequency signal to event risk without changing raw logs."""
    frequencies: dict[tuple[str, int], int] = {}
    for item in rows:
        key = (text(item.get("log")), int(item.get("event_id", 0) or 0))
        frequencies[key] = frequencies.get(key, 0) + 1

    for item in rows:
        key = (text(item.get("log")), int(item.get("event_id", 0) or 0))
        frequency = frequencies.get(key, 1)
        base = calculate_event_risk(item)
        frequency_bonus = 10 if frequency >= 10 else 5 if frequency >= 5 else 0
        score = max(0, min(100, base + frequency_bonus))
        item["risk"] = score
        item["risk_band"] = risk_band(score)


def event_item(log_name: str, record: Any) -> dict[str, Any]:
    event_id = int(getattr(record, "EventID", 0)) & 0xFFFF
    record_number = int(getattr(record, "RecordNumber", 0))
    source = text(getattr(record, "SourceName", "Windows"))
    computer = text(getattr(record, "ComputerName", ""))

    try:
        event_time = record.TimeGenerated.Format("%Y-%m-%d %H:%M:%S")
    except Exception:
        event_time = ""

    inserts = getattr(record, "StringInserts", None)
    if inserts:
        try:
            message = " | ".join(text(x) for x in inserts[:10])
        except Exception:
            message = text(inserts)
    else:
        message = ""

    event_type = int(getattr(record, "EventType", 0))
    level = {
        1: "ERROR",
        2: "WARNING",
        4: "INFO",
        8: "AUDIT",
        16: "AUDIT SUCCESS",
        32: "AUDIT FAILURE",
    }.get(event_type, "EVENT")

    return {
        "key": f"{log_name}:{record_number}",
        "time": event_time,
        "log": log_name,
        "event_id": event_id,
        "source": source,
        "level": level,
        "computer": computer,
        "message": message,
        "record": record_number,
        "risk": 0,
        "risk_band": "LOW",
    }


class EventModel(QAbstractTableModel):
    headers = ["TIME", "LOG", "EVENT ID", "SOURCE", "LEVEL", "RISK", "COMPUTER", "MESSAGE"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, Any]] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        item = self.rows[index.row()]
        values = [
            item["time"],
            item["log"],
            item["event_id"],
            item["source"],
            item["level"],
            f'{item.get("risk", 0)} • {item.get("risk_band", "LOW")}',
            item["computer"],
            item["message"],
        ]
        return text(values[index.column()])

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role=Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return str(section + 1)

    def replace(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class SimpleTableModel(QAbstractTableModel):
    def __init__(self, headers: list[str]) -> None:
        super().__init__()
        self.headers = headers
        self.rows: list[list[str]] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        return self.rows[index.row()][index.column()]

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return str(section + 1)

    def replace(self, rows: list[list[str]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class EventWorker(QObject):
    events = pyqtSignal(list)
    status = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.running = True
        self.seen: set[str] = set()
        self.last_record: dict[str, int] = {}

    def stop(self) -> None:
        self.running = False

    def read_backwards(self, log_name: str, limit: int) -> list[dict[str, Any]]:
        if win32evtlog is None:
            return []
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
        except Exception as exc:
            LOGGER.warning("%s unavailable: %s", log_name, exc)
            return []

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )
        result = []
        try:
            while self.running and len(result) < limit:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for record in batch:
                    item = event_item(log_name, record)
                    if item["key"] not in self.seen:
                        self.seen.add(item["key"])
                        result.append(item)
                        if len(result) >= limit:
                            break
        except Exception as exc:
            LOGGER.debug("%s history read: %s", log_name, exc)
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
        return result

    def current_record(self, log_name: str) -> int:
        if win32evtlog is None:
            return 0
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
            oldest = win32evtlog.GetOldestEventLogRecord(handle)
            count = win32evtlog.GetNumberOfEventLogRecords(handle)
            win32evtlog.CloseEventLog(handle)
            return oldest + max(count - 1, 0)
        except Exception:
            return 0

    def read_forward(self, log_name: str, after: int) -> list[dict[str, Any]]:
        if win32evtlog is None:
            return []
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
        except Exception:
            return []

        flags = (
            win32evtlog.EVENTLOG_FORWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )
        result = []
        try:
            # The Win32 API offset is a record number. Starting from the
            # current baseline avoids replaying the historical batch.
            while self.running:
                batch = win32evtlog.ReadEventLog(handle, flags, after)
                if not batch:
                    break
                for record in batch:
                    number = int(getattr(record, "RecordNumber", 0))
                    if number <= after:
                        continue
                    item = event_item(log_name, record)
                    after = max(after, number)
                    self.last_record[log_name] = after
                    if item["key"] not in self.seen:
                        self.seen.add(item["key"])
                        result.append(item)
                if len(batch) < 1:
                    break
        except Exception as exc:
            LOGGER.debug("%s live read: %s", log_name, exc)
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
        return result

    def run(self) -> None:
        try:
            if win32evtlog is None:
                self.status.emit("pywin32 missing • install pywin32")
                return

            # 400 per log gives enough real history for the 1000-event
            # rolling window without creating a huge UI workload.
            history: list[dict[str, Any]] = []
            for log_name in ("System", "Application", "Security"):
                if not self.running:
                    return
                history.extend(self.read_backwards(log_name, 400))
                self.last_record[log_name] = self.current_record(log_name)

            history.sort(
                key=lambda x: (x["time"], x["record"]),
                reverse=True,
            )
            self.events.emit(history[:EVENT_LIMIT])
            self.status.emit(
                f"Windows telemetry loaded • {min(len(history), EVENT_LIMIT)} real events"
            )

            while self.running:
                live: list[dict[str, Any]] = []
                for log_name in ("System", "Application", "Security"):
                    if not self.running:
                        break
                    live.extend(
                        self.read_forward(
                            log_name,
                            self.last_record.get(log_name, 0),
                        )
                    )

                if live:
                    live.sort(
                        key=lambda x: (x["time"], x["record"]),
                        reverse=True,
                    )
                    self.events.emit(live)

                for _ in range(int(EVENT_POLL_SECONDS * 10)):
                    if not self.running:
                        break
                    time.sleep(0.1)
        finally:
            self.finished.emit()


class DeviceWorker(QObject):
    devices = pyqtSignal(list, list)
    activity = pyqtSignal(dict)
    status = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.running = True
        self.last_wpd: set[str] = set()
        self.last_drives: set[str] = set()
        self.last_scan = 0.0
        self.previous_mtp: dict[str, dict[str, Any]] = {}

    def stop(self) -> None:
        self.running = False

    def emit_device_changes(
        self,
        wpd: list[dict[str, Any]],
        drives: list[dict[str, Any]],
    ) -> None:
        current_wpd = {x["name"] for x in wpd}
        current_drives = {x["drive"] for x in drives}

        for name in sorted(current_wpd - self.last_wpd):
            self.activity.emit(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "MTP DEVICE CONNECTED",
                    "device": name,
                    "drive": "MTP / WPD",
                    "file": name,
                    "size": "N/A",
                    "path": name,
                }
            )

        for name in sorted(self.last_wpd - current_wpd):
            self.activity.emit(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "MTP DEVICE DISCONNECTED",
                    "device": name,
                    "drive": "MTP / WPD",
                    "file": name,
                    "size": "N/A",
                    "path": name,
                }
            )

        for drive in sorted(current_drives - self.last_drives):
            self.activity.emit(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "USB DRIVE CONNECTED",
                    "device": "USB",
                    "drive": drive,
                    "file": "",
                    "size": "N/A",
                    "path": drive,
                }
            )

        for drive in sorted(self.last_drives - current_drives):
            self.activity.emit(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "USB DRIVE REMOVED",
                    "device": "USB",
                    "drive": drive,
                    "file": "",
                    "size": "N/A",
                    "path": drive,
                }
            )

        self.last_wpd = current_wpd
        self.last_drives = current_drives

    def mtp_snapshot(
        self,
        wpd: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """
        Lightweight top-level WPD snapshot.

        This intentionally avoids recursively walking an entire phone. A
        recursive MTP crawl can make Windows Explorer/COM stall for minutes
        on phones containing thousands of objects. Presence detection remains
        independent, so the UI cannot hang just because the phone is large.
        """
        if not wpd or win32com is None:
            return {}

        if pythoncom is not None:
            pythoncom.CoInitialize()

        try:
            shell = win32com.client.Dispatch("Shell.Application")
            root = shell.NameSpace(17)
            if root is None:
                return {}

            targets = {x["name"].casefold() for x in wpd}
            result: dict[str, dict[str, Any]] = {}

            for item in root.Items():
                name = text(getattr(item, "Name", "")).strip()
                if name.casefold() not in targets:
                    continue

                folder = getattr(item, "GetFolder", None)
                if folder is None:
                    continue

                # Only top-level objects. This is deliberately bounded.
                count = 0
                for child in folder.Items():
                    if count >= 300:
                        break
                    child_name = text(getattr(child, "Name", "")).strip()
                    if not child_name:
                        continue
                    is_folder = bool(getattr(child, "IsFolder", False))
                    if is_folder:
                        continue
                    try:
                        size = int(getattr(child, "Size", 0))
                    except (TypeError, ValueError):
                        size = 0
                    key = f"{name}|{child_name}".casefold()
                    result[key] = {
                        "device": name,
                        "name": child_name,
                        "size": size,
                        "modified": text(getattr(child, "ModifyDate", "")),
                    }
                    count += 1
            return result
        except Exception as exc:
            LOGGER.debug("MTP snapshot failed safely: %s", exc)
            return {}
        finally:
            if pythoncom is not None:
                pythoncom.CoUninitialize()

    def compare_mtp(
        self,
        current: dict[str, dict[str, Any]],
    ) -> None:
        old = self.previous_mtp

        for key in current.keys() - old.keys():
            x = current[key]
            self.activity.emit(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "MTP FILE OBSERVED",
                    "device": x["device"],
                    "drive": "MTP / WPD",
                    "file": x["name"],
                    "size": bytes_text(x["size"]),
                    "path": f'{x["device"]}\\{x["name"]}',
                }
            )

        for key in current.keys() & old.keys():
            a = old[key]
            b = current[key]
            if a["size"] != b["size"] or a["modified"] != b["modified"]:
                self.activity.emit(
                    {
                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "action": "MTP FILE CHANGED",
                        "device": b["device"],
                        "drive": "MTP / WPD",
                        "file": b["name"],
                        "size": bytes_text(b["size"]),
                        "path": f'{b["device"]}\\{b["name"]}',
                    }
                )

        for key in old.keys() - current.keys():
            x = old[key]
            self.activity.emit(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "MTP FILE REMOVED",
                    "device": x["device"],
                    "drive": "MTP / WPD",
                    "file": x["name"],
                    "size": bytes_text(x["size"]),
                    "path": f'{x["device"]}\\{x["name"]}',
                }
            )

        self.previous_mtp = current

    def run(self) -> None:
        try:
            while self.running:
                # Device presence is always scanned first and emitted
                # independently of the slower optional MTP file snapshot.
                wpd, drives = windows_devices()
                self.devices.emit(wpd, drives)
                self.emit_device_changes(wpd, drives)

                names = ", ".join(x["name"] for x in wpd)
                self.status.emit(
                    f"DEVICE MONITORING • {len(wpd)} WPD • {len(drives)} USB DRIVE(S)"
                    + (f" • {names}" if names else "")
                )

                if (
                    wpd
                    and time.monotonic() - self.last_scan >= MTP_POLL_SECONDS
                ):
                    snapshot = self.mtp_snapshot(wpd)
                    if snapshot:
                        self.compare_mtp(snapshot)
                    self.last_scan = time.monotonic()

                for _ in range(int(DEVICE_POLL_SECONDS * 10)):
                    if not self.running:
                        break
                    time.sleep(0.1)
        finally:
            self.finished.emit()


class GlassPanel(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("glass")


class Background(QWidget):
    """
    Non-native video background painted directly by Qt.

    QVideoSink receives the decoded FFmpeg frames and QPainter paints
    the latest frame directly onto this widget, keeping the SOC UI
    above the video layer.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents,
            True,
        )

        self.setStyleSheet("background: #03080d;")

        self.player = QMediaPlayer(self)

        self.audio = QAudioOutput(self)
        self.audio.setVolume(0.0)
        self.player.setAudioOutput(self.audio)

        self.sink = QVideoSink(self)
        self.player.setVideoSink(self.sink)

        self.sink.videoFrameChanged.connect(
            self._frame_changed
        )

        self.player.mediaStatusChanged.connect(
            self._media_status
        )

        self._frame_pixmap = QPixmap()
        self._scaled_pixmap = QPixmap()
        self._frame_count = 0

        if VIDEO_PATH.exists():
            LOGGER.info(
                "Loading background video: %s",
                VIDEO_PATH,
            )

            self.player.setSource(
                QUrl.fromLocalFile(str(VIDEO_PATH))
            )

            self.player.play()

        else:
            LOGGER.error(
                "Background video not found: %s",
                VIDEO_PATH,
            )

    def _frame_changed(self, frame) -> None:
        """Receive and store decoded video frames."""
        try:
            if not frame.isValid():
                return

            image = frame.toImage()

            if image.isNull():
                return

            pixmap = QPixmap.fromImage(image)

            if pixmap.isNull():
                return

            self._frame_pixmap = pixmap
            self._frame_count += 1

            if self._frame_count % 60 == 0:
                LOGGER.info(
                    "Background video frames received: %s",
                    self._frame_count,
                )

            self._update_scaled_pixmap()
            self.update()

        except Exception as exc:
            LOGGER.debug(
                "Video frame conversion failed: %s",
                exc,
            )

    def _update_scaled_pixmap(self) -> None:
        """Scale the latest video frame to fill the window."""
        if self._frame_pixmap.isNull():
            return

        target = self.size()

        if target.width() <= 0 or target.height() <= 0:
            return

        self._scaled_pixmap = self._frame_pixmap.scaled(
            target,
            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
            Qt.TransformationMode.FastTransformation,
        )

    def paintEvent(self, event) -> None:
        """Paint the current video frame."""
        painter = QPainter(self)

        painter.fillRect(
            self.rect(),
            Qt.GlobalColor.black,
        )

        if not self._scaled_pixmap.isNull():
            x = (
                self.width()
                - self._scaled_pixmap.width()
            ) // 2

            y = (
                self.height()
                - self._scaled_pixmap.height()
            ) // 2

            painter.drawPixmap(
                x,
                y,
                self._scaled_pixmap,
            )

        painter.end()

        super().paintEvent(event)

    def resizeEvent(self, event) -> None:
        """Resize the video when the application window changes."""
        self._update_scaled_pixmap()
        self.update()
        super().resizeEvent(event)

    def _media_status(self, status) -> None:
        """Loop the background video."""
        if status == QMediaPlayer.MediaStatus.EndOfMedia:
            LOGGER.info("Background video ended; restarting.")

            self.player.setPosition(0)
            self.player.play()

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("THREAT VISION • Insider Threat Predictor")
        self.resize(1500, 900)
        self.setMinimumSize(1150, 700)

        self.event_rows: deque[dict[str, Any]] = deque(maxlen=EVENT_LIMIT)
        self.event_keys: set[str] = set()
        self.usb_rows: deque[dict[str, Any]] = deque(maxlen=USB_ACTIVITY_LIMIT)
        self.current_event_filter = "ALL"
        self._pending_events: list[dict[str, Any]] = []
        self._event_refresh_timer = QTimer(self)
        self._event_refresh_timer.setSingleShot(True)
        self._event_refresh_timer.setInterval(GUI_EVENT_REFRESH_MS)
        self._event_refresh_timer.timeout.connect(self._process_pending_events)

        self.event_thread: QThread | None = None
        self.event_worker: EventWorker | None = None
        self.device_thread: QThread | None = None
        self.device_worker: DeviceWorker | None = None

        self.build_ui()
        self.start_workers()

    def build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        bg = Background(root)
        bg.setGeometry(0, 0, self.width(), self.height())
        self.bg = bg
        bg.lower()

        content = QVBoxLayout(root)
        content.setContentsMargins(22, 18, 22, 20)
        content.setSpacing(10)

        # Premium SOC header.
        header = GlassPanel()
        header.setObjectName("topGlass")
        h = QHBoxLayout(header)
        h.setContentsMargins(20, 14, 20, 14)

        left = QVBoxLayout()
        left.setSpacing(2)
        title = QLabel("THREAT VISION")
        title.setObjectName("title")
        sub = QLabel(
            "INSIDER THREAT PREDICTOR  •  LIVE WINDOWS SECURITY TELEMETRY"
        )
        sub.setObjectName("sub")
        left.addWidget(title)
        left.addWidget(sub)

        self.status = QLabel("● MONITORING")
        self.status.setObjectName("live")
        h.addLayout(left, 1)
        h.addWidget(self.status)

        # Navigation buttons are real page controls, not decorative labels.
        nav = QHBoxLayout()
        nav.setSpacing(10)

        self.dashboard_btn = self.nav_button("▣  Dashboard", 0)
        self.live_btn = self.nav_button("◉  Live Security", 1)
        self.usb_btn = self.nav_button("▤  USB Security", 2)
        self.project_btn = self.nav_button("ⓘ  Project Info", 3)
        self.exit_btn = self.nav_button("×  Exit", -1)

        self.dashboard_btn.clicked.connect(lambda: self.show_page(0))
        self.live_btn.clicked.connect(lambda: self.show_page(1))
        self.usb_btn.clicked.connect(lambda: self.show_page(2))
        self.project_btn.clicked.connect(lambda: self.show_page(3))
        self.exit_btn.clicked.connect(self.close)

        nav.addWidget(self.dashboard_btn)
        nav.addWidget(self.live_btn)
        nav.addWidget(self.usb_btn)
        nav.addStretch(1)
        nav.addWidget(self.exit_btn)

        self.pages = QStackedWidget()
        self.pages.addWidget(self.dashboard())
        self.pages.addWidget(self.events_page())
        self.pages.addWidget(self.usb_page())
        self.pages.addWidget(self.project_info_page())
        self.pages.currentChanged.connect(self.update_nav)

        content.addWidget(header)
        content.addLayout(nav)
        content.addWidget(self.pages, 1)

        self.show_page(0)

    def nav_button(self, label: str, index: int) -> QPushButton:
        button = QPushButton(label)
        button.setObjectName("navButton")
        button.setProperty("pageIndex", index)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setMinimumHeight(40)
        button.setMinimumWidth(126 if index >= 0 else 82)
        return button

    def show_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)

    def update_nav(self, index: int) -> None:
        for button in (
            self.dashboard_btn,
            self.live_btn,
            self.usb_btn,
            self.project_btn,
        ):
            button.setProperty(
                "active",
                button.property("pageIndex") == index,
            )
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

    def dashboard(self) -> QWidget:
        """Build the SOC overview dashboard."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(12)

        cards = QGridLayout()
        cards.setSpacing(10)

        self.event_card = self.card("WINDOWS EVENT MONITOR", "MONITORING")
        self.wpd_card = self.card("WPD / MTP DEVICES", "0")
        self.usb_card = self.card("USB ACTIVITY", "0")
        self.state_card = self.card("MONITOR STATE", "LIVE")

        cards.addWidget(self.event_card, 0, 0)
        cards.addWidget(self.wpd_card, 0, 1)
        cards.addWidget(self.usb_card, 0, 2)
        cards.addWidget(self.state_card, 0, 3)

        self.dashboard_project_info = QPushButton("PROJECT INFO")
        self.dashboard_project_info.setObjectName("dashboardProjectInfo")
        self.dashboard_project_info.setCursor(Qt.CursorShape.PointingHandCursor)
        self.dashboard_project_info.setMinimumHeight(40)
        self.dashboard_project_info.clicked.connect(lambda: self.show_page(3))
        cards.addWidget(self.dashboard_project_info, 1, 3)

        overview = GlassPanel()
        overview.setObjectName("overviewPanel")
        overview_layout = QVBoxLayout(overview)
        overview_layout.setContentsMargins(20, 18, 20, 18)
        overview_layout.setSpacing(12)

        heading = QLabel("SECURITY OPERATIONS")
        heading.setObjectName("page")

        description = QLabel(
            "Live Windows telemetry is active. Use the modules below to "
            "investigate security events and connected devices."
        )
        description.setObjectName("overviewText")
        description.setWordWrap(True)

        overview_layout.addWidget(heading)
        overview_layout.addWidget(description)

        modules = QGridLayout()
        modules.setSpacing(12)

        activity_panel = QFrame()
        activity_panel.setObjectName("dashboardModule")
        activity_box = QVBoxLayout(activity_panel)
        activity_box.setContentsMargins(16, 14, 16, 14)

        activity_title = QLabel("LIVE ACTIVITY")
        activity_title.setObjectName("moduleTitle")
        self.dashboard_feed = QPlainTextEdit()
        self.dashboard_feed.setObjectName("dashboardFeed")
        self.dashboard_feed.setReadOnly(True)
        self.dashboard_feed.setMinimumHeight(145)
        self.dashboard_feed.setPlaceholderText("Waiting for Windows telemetry…")
        activity_box.addWidget(activity_title)
        activity_box.addWidget(self.dashboard_feed)

        status_panel = QFrame()
        status_panel.setObjectName("dashboardModule")
        status_box = QVBoxLayout(status_panel)
        status_box.setContentsMargins(16, 14, 16, 14)

        status_title = QLabel("SYSTEM STATUS")
        status_title.setObjectName("moduleTitle")
        self.dashboard_status = QLabel(
            "WINDOWS EVENT LOG     ACTIVE\n"
            "SECURITY TELEMETRY   ACTIVE\n"
            "WPD / MTP MONITOR   READY\n"
            "USB MONITOR          READY\n"
            "RESPONSE MODE        SIMULATION"
        )
        self.dashboard_status.setObjectName("dashboardStatus")
        self.dashboard_status.setWordWrap(True)

        status_box.addWidget(status_title)
        status_box.addWidget(self.dashboard_status)
        status_box.addStretch(1)

        modules.addWidget(activity_panel, 0, 0)
        modules.addWidget(status_panel, 0, 1)

        overview_layout.addLayout(modules)
        layout.addLayout(cards)
        layout.addWidget(overview, 1)
        return page

    def events_page(self) -> QWidget:
        """Build the full live Windows security investigation page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(10)

        top_panel = GlassPanel()
        top_panel.setObjectName("eventHero")
        top = QHBoxLayout(top_panel)
        top.setContentsMargins(18, 14, 18, 14)

        title_box = QVBoxLayout()
        title = QLabel("FULL SECURITY EVENT STREAM")
        title.setObjectName("eventHeroTitle")
        subtitle = QLabel("REAL-TIME WINDOWS EVENT LOG TELEMETRY")
        subtitle.setObjectName("eventHeroSub")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        top.addLayout(title_box, 1)

        self.event_count = QLabel("● MONITORING • 0 REAL EVENTS")
        self.event_count.setObjectName("monitorCount")
        top.addWidget(self.event_count)

        dashboard_back = QPushButton("←  DASHBOARD")
        dashboard_back.setObjectName("pageAction")
        dashboard_back.clicked.connect(lambda: self.show_page(0))
        top.addWidget(dashboard_back)

        filter_bar = QFrame()
        filter_bar.setObjectName("eventFilterBar")
        filters = QHBoxLayout(filter_bar)
        filters.setContentsMargins(10, 8, 10, 8)
        filters.setSpacing(8)

        filter_label = QLabel("STREAM FILTER")
        filter_label.setObjectName("filterLabel")
        filters.addWidget(filter_label)

        self.event_filters = []
        for label, value in (
            ("ALL", "ALL"),
            ("SECURITY", "Security"),
            ("SYSTEM", "System"),
            ("APPLICATION", "Application"),
            ("⚠ ALERTS", "ALERTS"),
            ("◈ RISK", "RISK"),
        ):
            button = QPushButton(label)
            button.setObjectName("filterButton")
            if value == "ALERTS":
                button.setObjectName("alertFilterButton")
            elif value == "RISK":
                button.setObjectName("riskFilterButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda checked, v=value: self.set_event_filter(v)
            )
            self.event_filters.append((value, button))
            filters.addWidget(button)

        self.event_filters[0][1].setChecked(True)
        filters.addStretch(1)

        self.risk_status = QLabel("RISK SIGNAL • READY")
        self.risk_status.setObjectName("riskStatus")
        filters.addWidget(self.risk_status)

        live_label = QLabel("● LIVE STREAM")
        live_label.setObjectName("streamLive")
        filters.addWidget(live_label)

        table_panel = GlassPanel()
        table_panel.setObjectName("eventTablePanel")
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(10, 10, 10, 10)

        self.event_model = EventModel()
        self.event_view = self.table(self.event_model)
        self.event_view.setObjectName("eventTable")
        self.event_view.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.event_view.setMinimumHeight(300)
        self.event_view.clicked.connect(self.show_event_details)

        header = self.event_view.horizontalHeader()
        for col in range(7):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        table_layout.addWidget(self.event_view)

        detail_panel = GlassPanel()
        detail_panel.setObjectName("eventDetails")
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(18, 12, 18, 14)
        detail_layout.setSpacing(8)

        detail_header = QHBoxLayout()
        detail_title = QLabel("EVENT INSPECTOR")
        detail_title.setObjectName("detailTitle")
        self.detail_event_id = QLabel("SELECT AN EVENT")
        self.detail_event_id.setObjectName("detailEventId")
        detail_header.addWidget(detail_title)
        detail_header.addStretch()
        detail_header.addWidget(self.detail_event_id)
        detail_layout.addLayout(detail_header)

        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setObjectName("detailText")
        self.detail_text.setPlaceholderText(
            "Select an event above to inspect its details."
        )
        self.detail_text.setMinimumHeight(190)
        detail_layout.addWidget(self.detail_text)

        actions = QHBoxLayout()
        project_info = QPushButton("ⓘ  PROJECT INFO")
        project_info.setObjectName("pageAction")
        project_info.clicked.connect(lambda: self.show_page(3))
        actions.addWidget(project_info)
        actions.addStretch(1)
        detail_layout.addLayout(actions)

        layout.addWidget(top_panel)
        layout.addWidget(filter_bar)
        layout.addWidget(table_panel, 1)
        layout.addWidget(detail_panel)
        return page

    def set_event_filter(self, value: str) -> None:
        """Apply a stream, alert, or risk-analysis view without altering raw telemetry."""
        for filter_value, button in self.event_filters:
            button.setChecked(filter_value == value)

        self.current_event_filter = value
        rows = list(self.event_rows)

        if value == "SECURITY":
            rows = [row for row in rows if row.get("log") == "Security"]
        elif value == "SYSTEM":
            rows = [row for row in rows if row.get("log") == "System"]
        elif value == "APPLICATION":
            rows = [row for row in rows if row.get("log") == "Application"]
        elif value == "ALERTS":
            rows = [row for row in rows if is_alert_event(row)]
            rows.sort(
                key=lambda x: (int(x.get("risk", 0)), x.get("time", "")),
                reverse=True,
            )
        elif value == "RISK":
            # Risk mode keeps the complete real event population but puts the
            # strongest investigative signals first.
            rows.sort(
                key=lambda x: (int(x.get("risk", 0)), x.get("time", "")),
                reverse=True,
            )

        self.event_model.replace(rows)
        self.update_filter_status(rows, value)

    def update_filter_status(
        self,
        rows: list[dict[str, Any]],
        value: str,
    ) -> None:
        """Update the analyst-facing count and risk summary."""
        if value == "ALERTS":
            self.event_count.setText(
                f"⚠ ALERT VIEW • {len(rows):,} ALERT EVENTS"
            )
        elif value == "RISK":
            top = max((int(x.get("risk", 0)) for x in rows), default=0)
            average = (
                sum(int(x.get("risk", 0)) for x in rows) / len(rows)
                if rows else 0
            )
            self.event_count.setText(
                f"◈ RISK ANALYSIS • {len(rows):,} EVENTS • TOP {top}/100"
            )
            self.risk_status.setText(
                f"RISK SIGNAL • TOP {top}/100 • AVG {average:.0f}/100"
            )
        else:
            self.event_count.setText(
                f"● MONITORING • {len(rows):,} REAL EVENTS"
            )
            top = max((int(x.get("risk", 0)) for x in rows), default=0)
            self.risk_status.setText(f"RISK SIGNAL • TOP {top}/100")

    def refresh_event_filter(self) -> None:
        """Refresh the table using the currently selected stream filter."""
        value = getattr(self, "current_event_filter", "ALL")
        self.set_event_filter(value)

    def show_event_details(self, index: QModelIndex) -> None:
        row = index.row()
        if row < 0 or row >= len(self.event_model.rows):
            return
        item = self.event_model.rows[row]
        risk = int(item.get("risk", 0) or 0)
        band = item.get("risk_band", risk_band(risk))
        self.detail_event_id.setText(
            f"EVENT {item.get('event_id', '—')}  •  RISK {risk}/100"
        )
        raw = {
            "time": item.get("time", ""),
            "log": item.get("log", ""),
            "event_id": item.get("event_id", ""),
            "source": item.get("source", ""),
            "computer": item.get("computer", ""),
            "severity": item.get("level", ""),
            "risk": risk,
            "risk_band": band,
            "record_number": item.get("record", ""),
            "message": item.get("message", ""),
        }
        self.detail_text.setPlainText(
            "TIME\n"
            f"{raw['time']}\n\n"
            "LOG\n"
            f"{raw['log']}\n\n"
            "EVENT ID\n"
            f"{raw['event_id']}\n\n"
            "SOURCE\n"
            f"{raw['source']}\n\n"
            "COMPUTER\n"
            f"{raw['computer']}\n\n"
            "SEVERITY\n"
            f"{raw['severity']}\n\n"
            "RISK SIGNAL\n"
            f"{raw['risk']}/100 • {raw['risk_band']}\n\n"
            "MESSAGE\n"
            f"{raw['message']}\n\n"
            "RAW NORMALIZED EVENT\n"
            f"{json.dumps(raw, ensure_ascii=False)}"
        )

    def project_info_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("projectInfoPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(10)

        hero = GlassPanel()
        hero.setObjectName("eventHero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(18, 14, 18, 14)
        title_box = QVBoxLayout()
        title = QLabel("THREATVISION • PROJECT INFORMATION")
        title.setObjectName("eventHeroTitle")
        subtitle = QLabel("INSIDER THREAT PREDICTOR • SECURITY OPERATIONS ARCHITECTURE")
        subtitle.setObjectName("eventHeroSub")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        hero_layout.addLayout(title_box, 1)
        back = QPushButton("←  BACK TO LIVE SECURITY")
        back.setObjectName("pageAction")
        back.clicked.connect(lambda: self.show_page(1))
        hero_layout.addWidget(back)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setObjectName("infoScroll")
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(18, 18, 18, 18)
        body_layout.setSpacing(16)

        sections = [
            ("PROJECT PURPOSE", "ThreatVision is a Windows desktop security operations tool designed to monitor user and system activity, surface behavioral security signals, and support insider-threat investigation in a consent-based environment."),
            ("CORE OBJECTIVES", "• Real-time Windows security telemetry\n• User and entity behavior analytics (UEBA) foundation\n• Insider-threat risk analysis\n• Security event investigation\n• USB, removable-drive and WPD/MTP visibility\n• Communication/sentiment analysis integration point\n• Explainable machine-learning integration\n• Controlled response automation with simulation-first behavior"),
            ("LIVE TELEMETRY", "The current desktop interface reads Windows Event Log telemetry from System, Application and Security logs. Events are maintained in a rolling in-memory window for the Live Security console. The UI presents real records available from the local Windows event logs rather than fabricating records."),
            ("USB / MTP SECURITY", "ThreatVision separates normal removable-drive monitoring from Windows Portable Device (WPD/MTP) monitoring. Android phones such as OPPO A59 5G can appear as WPD devices without a drive letter. File observations are presented as observations; MTP telemetry should not be interpreted as proof of copy direction unless Windows provides that evidence."),
            ("ANALYTICS & ML ARCHITECTURE", "The project architecture is designed around feature extraction, behavioral baselines, anomaly detection and risk scoring. The wider project specification includes pandas, NumPy, scikit-learn, XGBoost and SHAP for machine-learning and explainability workflows."),
            ("NLP / COMMUNICATION ANALYSIS", "The architecture provides an integration point for communication and sentiment analysis. Such analysis should be treated as one contextual signal among multiple telemetry sources rather than a standalone determination of malicious intent."),
            ("AUTOMATED RESPONSE", "Response actions are designed to be simulation-first. Real remediation actions should require explicit opt-in and confirmation. This keeps the application suitable for controlled testing and defensive security operations."),
            ("TECHNOLOGY", "Python 3.11+ architecture • PyQt6 desktop GUI • SQLite-compatible storage • Windows Event Log / Win32 telemetry • PowerShell PnP queries for WPD detection • optional watchdog file monitoring • modular collectors, analytics, NLP and response components."),
            ("PRIVACY & CONSENT", "Monitoring should be deployed only with appropriate authorization and user consent. The dashboard is intended for defensive security monitoring of systems the operator is authorized to monitor."),
            ("CURRENT UI MODULES", "Dashboard • Live Security • USB Security • Project Information • Exit. The Live Security console provides event inspection and event details. USB Security provides removable-drive and WPD/MTP device visibility."),
            ("PROJECT IDENTITY", "Name: ThreatVision: Inside Threat Predictor\nPrimary theme: enterprise SOC / behavioral security\nPlatform: Windows desktop\nInterface: dark glassmorphism with the supplied ThreatVision background video\nOperating mode: live Windows telemetry with monitoring status visible throughout the application."),
        ]

        for heading, content in sections:
            panel = GlassPanel()
            panel.setObjectName("infoPanel")
            box = QVBoxLayout(panel)
            box.setContentsMargins(18, 16, 18, 16)
            h = QLabel(heading)
            h.setObjectName("infoHeading")
            t = QLabel(content)
            t.setObjectName("infoBody")
            t.setWordWrap(True)
            box.addWidget(h)
            box.addWidget(t)
            body_layout.addWidget(panel)

        body_layout.addStretch(1)
        scroll.setWidget(body)
        layout.addWidget(hero)
        layout.addWidget(scroll, 1)
        return page

    def usb_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(10)

        top = QHBoxLayout()
        title = QLabel("USB SECURITY MONITOR")
        title.setObjectName("page")
        self.device_status = QLabel("DEVICE MONITORING • scanning…")
        self.device_status.setObjectName("monitorCount")
        top.addWidget(title)
        top.addStretch()
        top.addWidget(self.device_status)

        self.device_model = SimpleTableModel(
            ["TYPE", "DEVICE / DRIVE", "FILESYSTEM", "CAPACITY", "FREE", "STATUS"]
        )
        self.device_view = self.table(self.device_model)

        activity = QLabel("LIVE USB / MTP FILE ACTIVITY")
        activity.setObjectName("section")

        self.usb_model = SimpleTableModel(
            ["TIME", "ACTION", "DEVICE", "FILE", "SIZE", "PATH"]
        )
        self.usb_view = self.table(self.usb_model)

        layout.addLayout(top)
        layout.addWidget(self.device_view, 1)
        layout.addWidget(activity)
        layout.addWidget(self.usb_view, 1)
        return page

    def card(self, name: str, value: str) -> GlassPanel:
        card = GlassPanel()
        box = QVBoxLayout(card)
        name_label = QLabel(name)
        name_label.setObjectName("card_name")
        value_label = QLabel(value)
        value_label.setObjectName("card_value")
        box.addWidget(name_label)
        box.addWidget(value_label)
        card.value_label = value_label
        return card

    def table(self, model) -> QTableView:
        view = QTableView()
        view.setModel(model)
        view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        view.verticalHeader().setVisible(False)
        view.setAlternatingRowColors(False)
        view.horizontalHeader().setStretchLastSection(True)
        view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        view.setWordWrap(False)
        return view

    def start_workers(self) -> None:
        self.event_thread = QThread(self)
        self.event_worker = EventWorker()
        self.event_worker.moveToThread(self.event_thread)
        self.event_thread.started.connect(self.event_worker.run)
        self.event_worker.events.connect(self.on_events)
        self.event_worker.status.connect(self.on_event_status)
        self.event_worker.finished.connect(self.event_thread.quit)

        self.device_thread = QThread(self)
        self.device_worker = DeviceWorker()
        self.device_worker.moveToThread(self.device_thread)
        self.device_thread.started.connect(self.device_worker.run)
        self.device_worker.devices.connect(self.on_devices)
        self.device_worker.activity.connect(self.on_usb_activity)
        self.device_worker.status.connect(self.on_device_status)
        self.device_worker.finished.connect(self.device_thread.quit)

        self.event_thread.start()
        self.device_thread.start()

    def on_events(self, incoming: list[dict[str, Any]]) -> None:
        """Queue telemetry and coalesce GUI work into one refresh batch."""
        if not incoming:
            return
        self._pending_events.extend(incoming)
        if not self._event_refresh_timer.isActive():
            self._event_refresh_timer.start()

    def _process_pending_events(self) -> None:
        """Apply queued events once, rather than rebuilding the table per batch."""
        incoming = self._pending_events
        self._pending_events = []
        if not incoming:
            return

        changed = False
        for item in incoming:
            key = item["key"]
            if key in self.event_keys:
                continue
            self.event_keys.add(key)
            self.event_rows.append(item)
            changed = True

        if not changed:
            return

        rows = list(self.event_rows)
        rows.sort(key=lambda x: (x["time"], x["record"]), reverse=True)
        rows = rows[:EVENT_LIMIT]
        self.event_rows = deque(rows, maxlen=EVENT_LIMIT)
        self.event_keys = {x["key"] for x in rows}

        # Calculate the contextual risk signal once per changed batch.
        apply_contextual_risk(rows)
        self.event_rows = deque(rows, maxlen=EVENT_LIMIT)

        self.event_count_label_update(len(rows))

        if hasattr(self, "dashboard_feed"):
            feed_lines = [
                f'{item.get("time", "")}  |  {item.get("log", "")}  |  '
                f'ID {item.get("event_id", "")}  |  {item.get("level", "")}'
                for item in rows[:6]
            ]
            self.dashboard_feed.setPlainText(
                "\n".join(feed_lines) if feed_lines else "Waiting for Windows telemetry…"
            )

        self.refresh_event_filter()
        if rows and self.event_view.selectionModel() and not self.event_view.currentIndex().isValid():
            self.event_view.selectRow(0)
            self.show_event_details(self.event_model.index(0, 0))
        self.event_card.value_label.setText("MONITORING")

    def event_count_label_update(self, count: int) -> None:
        self.event_count.setText(f"● MONITORING • {count:,} REAL EVENTS")

    def on_event_status(self, message: str) -> None:
        self.status.setText("● MONITORING")
        self.state_card.value_label.setText("LIVE")
        self.event_card.value_label.setText("MONITORING")

    def on_devices(
        self,
        wpd: list[dict[str, Any]],
        drives: list[dict[str, Any]],
    ) -> None:
        rows = []
        for drive in drives:
            rows.append(
                [
                    "USB",
                    f'{drive["drive"]}  {drive["label"]}',
                    drive["filesystem"],
                    bytes_text(drive["size"]),
                    bytes_text(drive["free"]),
                    "CONNECTED",
                ]
            )
        for device in wpd:
            rows.append(
                [
                    "MTP / WPD",
                    device["name"],
                    "MTP / WPD",
                    "N/A",
                    "N/A",
                    device["status"],
                ]
            )

        self.device_model.replace(rows)
        self.wpd_card.value_label.setText(str(len(wpd)))

    def on_device_status(self, message: str) -> None:
        self.device_status.setText(message)

    def on_usb_activity(self, item: dict[str, Any]) -> None:
        self.usb_rows.appendleft(item)
        rows = [
            [
                x["time"],
                x["action"],
                x["device"] or x["drive"],
                x["file"],
                x["size"] if isinstance(x["size"], str) else bytes_text(x["size"]),
                x["path"],
            ]
            for x in list(self.usb_rows)
        ]
        self.usb_model.replace(rows)
        self.usb_card.value_label.setText(str(len(self.usb_rows)))

    def resizeEvent(self, event) -> None:
        if hasattr(self, "bg"):
            self.bg.setGeometry(0, 0, self.width(), self.height())
        super().resizeEvent(event)

    def closeEvent(self, event) -> None:
        if self.event_worker:
            self.event_worker.stop()
        if self.device_worker:
            self.device_worker.stop()

        if self.event_thread:
            self.event_thread.quit()
            self.event_thread.wait(3000)
        if self.device_thread:
            self.device_thread.quit()
            self.device_thread.wait(3000)
        event.accept()


STYLE = r"""
QMainWindow, QWidget {
    color: #edfaff;
    font-family: "Segoe UI";
    font-size: 12px;
    background: transparent;
}

#glass, #topGlass, #overviewPanel {
    background: rgba(4, 16, 28, 112);
    border: 1px solid rgba(55, 205, 250, 135);
    border-radius: 14px;
}

#topGlass {
    background: rgba(3, 15, 26, 92);
}

#title {
    color: #f7fdff;
    font-size: 25px;
    font-weight: 900;
    letter-spacing: 2px;
}

#sub {
    color: #78d8f2;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}

#live {
    color: #77f4d4;
    background: rgba(4, 47, 43, 165);
    border: 1px solid rgba(79, 255, 220, 130);
    border-radius: 10px;
    padding: 9px 18px;
    font-weight: 900;
}


#dashboardProjectInfo {
    color: #031116;
    background: #28d7e6;
    border: 1px solid #8af6ff;
    border-radius: 9px;
    padding: 8px 18px;
    font-size: 11px;
    font-weight: 900;
    letter-spacing: 1px;
}

#dashboardProjectInfo:hover {
    background: #58e6f0;
    border-color: #d0fcff;
}

#projectInfoPage {
    background: #010305;
    color: #eafaff;
}

#projectInfoPage #eventHero {
    background: #03090e;
    border: 1px solid rgba(64, 210, 238, 150);
}

#projectInfoPage #infoPanel {
    background: #050b10;
    border: 1px solid rgba(52, 174, 203, 105);
    border-left: 3px solid #22c9db;
    border-radius: 12px;
}

#projectInfoPage #infoHeading {
    color: #66e4f4;
}

#projectInfoPage #infoBody {
    color: #d8edf2;
}

#projectInfoPage #infoScroll,
#projectInfoPage QScrollArea,
#projectInfoPage QScrollArea > QWidget > QWidget {
    background: #010305;
}

#navButton {
    color: #eafaff;
    background: rgba(4, 24, 39, 150);
    border: 1px solid rgba(64, 202, 245, 125);
    border-radius: 9px;
    padding: 8px 16px;
    font-size: 12px;
    font-weight: 800;
}

#navButton:hover {
    background: rgba(20, 82, 108, 190);
    border-color: rgba(104, 229, 255, 205);
}

#navButton[active="true"] {
    color: #ffffff;
    background: rgba(17, 105, 137, 210);
    border: 1px solid rgba(117, 232, 255, 235);
}

#navButton[pageIndex="-1"] {
    min-width: 82px;
}

#card_name {
    color: #83d9f2;
    font-size: 10px;
    font-weight: 900;
    letter-spacing: 1px;
}

#card_value {
    color: #f5fdff;
    font-size: 20px;
    font-weight: 900;
}

#page {
    color: #f5fcff;
    font-size: 15px;
    font-weight: 900;
    letter-spacing: 1px;
}

#eventHero {
    background: rgba(4, 16, 28, 92);
}

#eventHeroTitle {
    color: #f7fdff;
    font-size: 18px;
    font-weight: 900;
    letter-spacing: 1px;
}

#eventHeroSub {
    color: #7fd9f3;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}

#pageAction {
    color: #edfaff;
    background: rgba(4, 28, 45, 150);
    border: 1px solid rgba(85, 207, 244, 150);
    border-radius: 9px;
    padding: 8px 15px;
    font-weight: 800;
}

#pageAction:hover {
    background: rgba(17, 92, 120, 190);
    border-color: rgba(126, 235, 255, 220);
}

#eventTablePanel, #eventDetails, #infoPanel {
    background: rgba(4, 16, 28, 88);
    border: 1px solid rgba(55, 205, 250, 105);
    border-radius: 14px;
}

#detailTitle {
    color: #f5fcff;
    font-size: 14px;
    font-weight: 900;
    letter-spacing: 1px;
}

#detailEventId {
    color: #f3d68a;
    font-size: 11px;
    font-weight: 900;
}

#inspectorLabel {
    color: #86d8ed;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}

#detailText {
    background: rgba(2, 10, 18, 80);
    border: 1px solid rgba(71, 190, 225, 75);
    border-radius: 10px;
    color: #dff6ff;
    font-family: Consolas, monospace;
    font-size: 11px;
    padding: 10px;
}

#infoScroll {
    background: transparent;
    border: none;
}

#infoHeading {
    color: #7edcf5;
    font-size: 12px;
    font-weight: 900;
    letter-spacing: 1px;
}

#infoBody {
    color: #d5edf5;
    font-size: 12px;
    line-height: 1.45;
}

#monitorCount {
    color: #72f0d0;
    font-size: 11px;
    font-weight: 900;
    padding: 6px 12px;
    background: rgba(3, 48, 43, 125);
    border: 1px solid rgba(75, 245, 215, 95);
    border-radius: 8px;
}

#section {
    color: #7fd9f3;
    font-weight: 900;
    padding: 6px;
}

#overviewText, #hint {
    color: #b6d9e5;
    font-size: 13px;
}

#hint {
    color: #75d8f2;
    font-weight: 700;
    padding: 5px 0;
}


#dashboardModule {
    background: rgba(2, 13, 22, 105);
    border: 1px solid rgba(55, 194, 230, 92);
    border-radius: 11px;
}

#moduleTitle {
    color: #69e1f2;
    font-size: 11px;
    font-weight: 900;
    letter-spacing: 1px;
}

#dashboardFeed {
    background: rgba(0, 7, 12, 85);
    border: 1px solid rgba(61, 184, 216, 60);
    border-radius: 8px;
    color: #dff8ff;
    font-family: Consolas, monospace;
    font-size: 11px;
    padding: 8px;
}

#dashboardStatus {
    color: #cdebf2;
    font-family: Consolas, monospace;
    font-size: 11px;
    line-height: 1.5;
}

#eventFilterBar {
    background: rgba(2, 12, 20, 150);
    border: 1px solid rgba(57, 193, 226, 90);
    border-radius: 10px;
}

#filterLabel {
    color: #6fdff2;
    font-size: 10px;
    font-weight: 900;
    letter-spacing: 1px;
    padding-right: 5px;
}

#filterButton {
    color: #bfeaf3;
    background: rgba(5, 28, 41, 145);
    border: 1px solid rgba(59, 189, 221, 100);
    border-radius: 7px;
    padding: 6px 13px;
    font-size: 10px;
    font-weight: 800;
}

#filterButton:hover {
    background: rgba(16, 76, 96, 180);
}

#filterButton:checked {
    color: #031116;
    background: #28d7e6;
    border-color: #8af6ff;
}

#alertFilterButton {
    color: #ffd98a;
    background: rgba(74, 46, 8, 145);
    border: 1px solid rgba(255, 191, 72, 155);
    border-radius: 7px;
    padding: 6px 13px;
    font-size: 10px;
    font-weight: 900;
}

#alertFilterButton:hover {
    background: rgba(122, 75, 8, 185);
    border-color: #ffd477;
}

#alertFilterButton:checked {
    color: #1a0e00;
    background: #ffc85a;
    border-color: #ffe2a2;
}

#riskFilterButton {
    color: #e6c8ff;
    background: rgba(63, 24, 87, 150);
    border: 1px solid rgba(202, 129, 255, 155);
    border-radius: 7px;
    padding: 6px 13px;
    font-size: 10px;
    font-weight: 900;
}

#riskFilterButton:hover {
    background: rgba(93, 35, 127, 190);
    border-color: #dca8ff;
}

#riskFilterButton:checked {
    color: #170c22;
    background: #d59aff;
    border-color: #f0d5ff;
}

#riskStatus {
    color: #e4c6ff;
    background: rgba(49, 22, 69, 120);
    border: 1px solid rgba(188, 118, 239, 95);
    border-radius: 7px;
    padding: 6px 10px;
    font-size: 9px;
    font-weight: 900;
    letter-spacing: 0.5px;
}

#streamLive {
    color: #70f0d2;
    font-size: 10px;
    font-weight: 900;
    letter-spacing: 1px;
}

QTableView {
    background: rgba(2, 11, 20, 78);
    border: 1px solid rgba(65, 193, 233, 105);
    border-radius: 11px;
    color: #edfaff;
    gridline-color: rgba(75, 180, 215, 42);
    selection-background-color: rgba(28, 111, 145, 180);
    selection-color: white;
    alternate-background-color: rgba(7, 24, 38, 72);
}

QTableView::item {
    padding: 7px;
}

QHeaderView::section {
    background: rgba(4, 27, 40, 190);
    color: #91e5fb;
    border: 0;
    border-bottom: 1px solid rgba(80, 210, 250, 115);
    padding: 8px;
    font-size: 10px;
    font-weight: 900;
}

QScrollBar:vertical {
    background: rgba(2, 8, 14, 80);
    width: 9px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: rgba(71, 178, 215, 145);
    border-radius: 4px;
    min-height: 28px;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0px;
}
"""



def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())