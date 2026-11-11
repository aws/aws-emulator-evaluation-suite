"""detect-sentiment-negative-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-sentiment-negative-text"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSentiment classifies an unambiguously negative English text as NEGATIVE."""
    comprehend = ctx.client("comprehend")
    text = (
        "This is the worst experience I have ever had. The product broke immediately, "
        "support was rude, and I regret this purchase completely."
    )
    resp = comprehend.detect_sentiment(Text=text, LanguageCode="en")
    assert resp["Sentiment"] == "NEGATIVE", f"expected NEGATIVE, got {resp['Sentiment']!r}"
    scores = resp["SentimentScore"]
    total = scores["Positive"] + scores["Negative"] + scores["Neutral"] + scores["Mixed"]
    assert abs(total - 1.0) < 0.02, f"sentiment score components should sum to ~1.0, got {total} ({scores!r})"
    assert scores["Negative"] == max(scores.values()), (
        f"Negative should be the dominant score component, got {scores!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
