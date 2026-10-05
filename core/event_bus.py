"""Thread-safe event bus."""

from __future__ import annotations
import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from typing import Any

log = logging.getLogger("threatvision.event_bus")


class EventBus:
    """Simple thread-safe publish/subscribe bus."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[Any], None]]] = defaultdict(list)
        self._lock = threading.RLock()

    def subscribe(self, event: str, handler: Callable[[Any], None]) -> None:
        with self._lock:
            if handler not in self._handlers[event]:
                self._handlers[event].append(handler)

    def publish(self, event: str, payload: Any = None) -> None:
        with self._lock:
            handlers = tuple(self._handlers.get(event, ()))
        for handler in handlers:
            try:
                handler(payload)
            except Exception:
                log.exception("Event handler failed: %s", event)
