"""detect-sentiment-positive-text-scores-consistent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-sentiment-positive-text-scores-consistent"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSentiment on unambiguous positive text reports POSITIVE and internally-consistent scores."""
    comprehend = ctx.client("comprehend")
    text = (
        "I absolutely love this product, it is wonderful and amazing and made my day so much better!"
    )
    resp = comprehend.detect_sentiment(Text=text, LanguageCode="en")

    scores = resp["SentimentScore"]
    total = scores["Positive"] + scores["Negative"] + scores["Neutral"] + scores["Mixed"]
    assert abs(total - 1.0) < 0.02, f"sentiment scores do not sum to ~1.0: {scores!r}"

    # The reported Sentiment must be the argmax of the four component scores.
    ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_key = ordered[0][0]
    assert resp["Sentiment"] == top_key.upper(), (
        f"Sentiment={resp['Sentiment']!r} does not match argmax score component {top_key!r} ({scores!r})"
    )

    # For this clearly positive text, AWS Comprehend's built-in model reports POSITIVE.
    assert resp["Sentiment"] == "POSITIVE", f"expected POSITIVE, got {resp['Sentiment']!r} ({scores!r})"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
