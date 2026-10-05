"""Keyword-based intent indicators."""

from __future__ import annotations

KEYWORDS = {
    "exfiltration": {"upload", "download", "copy", "export", "transfer", "data"},
    "resignation": {"resign", "leaving", "quit", "notice"},
    "grievance": {"complaint", "unfair", "grievance", "manager", "pay"},
}


def detect_intents(text: str) -> list[str]:
    """Return intent categories whose keyword sets are present."""
    words = {word.strip(".,!?;:").lower() for word in text.split()}
    return [name for name, terms in KEYWORDS.items() if words & terms]
