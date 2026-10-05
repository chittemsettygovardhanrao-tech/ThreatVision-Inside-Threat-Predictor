"""Logging configuration."""

from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(path: Path = Path("logs/threatvision.log")) -> logging.Logger:
    """Configure rotating application logging."""
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("threatvision")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(threadName)s | %(message)s"
    )
    handler = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(console)
    logger.propagate = False
    return logger
