from threatvision.nlp.sentiment_analyzer import SentimentAnalyzer
from threatvision.nlp.keyword_intent import detect_intents


def test_sentiment():
    result = SentimentAnalyzer().analyze("alice", "I am happy with this project.")
    assert -1 <= result.compound <= 1


def test_keywords():
    assert "resignation" in detect_intents("I am going to resign")
