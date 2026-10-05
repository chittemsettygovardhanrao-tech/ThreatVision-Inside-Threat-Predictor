"""Simulation-only response action dispatcher."""

from __future__ import annotations
import logging

log = logging.getLogger("threatvision.response")


class ActionDispatcher:
    """Log response decisions; never perform high-impact actions by default."""

    def __init__(self, live_mode: bool = False) -> None:
        self.live_mode = live_mode

    def execute(self, action: str, user_id: str, reason: str) -> dict[str, str]:
        mode = "LIVE" if self.live_mode else "SIMULATION"
        log.warning(
            "Response action=%s user=%s mode=%s reason=%s",
            action, user_id, mode, reason,
        )
        return {"action": action, "user_id": user_id, "mode": mode, "status": "simulated"}
