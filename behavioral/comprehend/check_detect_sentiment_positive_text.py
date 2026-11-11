"""detect-sentiment-positive-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-sentiment-positive-text"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSentiment classifies an unambiguously positive English text as POSITIVE
    and the four SentimentScore components sum to ~1.0 with Positive dominant."""
    comprehend = ctx.client("comprehend")
    text = (
        "I absolutely love this new phone, it is wonderful and has exceeded every one "
        "of my expectations. Best purchase I have made all year!"
    )
    resp = comprehend.detect_sentiment(Text=text, LanguageCode="en")
    assert resp["Sentiment"] == "POSITIVE", f"expected POSITIVE, got {resp['Sentiment']!r}"
    scores = resp["SentimentScore"]
    total = scores["Positive"] + scores["Negative"] + scores["Neutral"] + scores["Mixed"]
    assert abs(total - 1.0) < 0.02, f"sentiment score components should sum to ~1.0, got {total}"
    assert scores["Positive"] == max(scores.values()), (
        f"Positive should be the dominant score component, got {scores!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
