"""Privacy-preserving VADER sentiment analysis."""

from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from threatvision.core.models import SentimentResult


class SentimentAnalyzer:
    """Analyze text while returning no message body."""

    def __init__(self, salt: str = "threatvision-local") -> None:
        self.analyzer = SentimentIntensityAnalyzer()
        self.salt = salt

    def analyze(self, user_id: str, text: str) -> SentimentResult:
        scores = self.analyzer.polarity_scores(text)
        digest = hashlib.sha256((self.salt + user_id).encode()).hexdigest()
        return SentimentResult(
            user_hash=digest,
            timestamp=datetime.now(timezone.utc),
            compound=scores["compound"],
            positive=scores["pos"],
            neutral=scores["neu"],
            negative=scores["neg"],
        )
