"""detect-sentiment-polarity-matches-content."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-sentiment-polarity-matches-content"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSentiment returns POSITIVE for clearly positive text and NEGATIVE for clearly
    negative text, with SentimentScore's dominant field matching the reported Sentiment."""
    comprehend = ctx.client("comprehend")

    positive = comprehend.detect_sentiment(
        Text="Today is my birthday, I am so happy.", LanguageCode="en"
    )
    assert positive["Sentiment"] == "POSITIVE", (
        f"expected POSITIVE for unambiguously positive text, got {positive['Sentiment']!r} "
        f"({positive['SentimentScore']!r})"
    )
    pos_scores = positive["SentimentScore"]
    pos_total = sum(pos_scores.values())
    assert abs(pos_total - 1.0) < 0.02, f"SentimentScore components should sum to ~1.0, got {pos_scores!r}"
    assert pos_scores["Positive"] == max(pos_scores.values()), (
        f"expected Positive to be the dominant component, got {pos_scores!r}"
    )

    negative = comprehend.detect_sentiment(
        Text="This is the worst day of my life, everything went wrong and I am furious.",
        LanguageCode="en",
    )
    assert negative["Sentiment"] == "NEGATIVE", (
        f"expected NEGATIVE for unambiguously negative text, got {negative['Sentiment']!r} "
        f"({negative['SentimentScore']!r})"
    )
    neg_scores = negative["SentimentScore"]
    neg_total = sum(neg_scores.values())
    assert abs(neg_total - 1.0) < 0.02, f"SentimentScore components should sum to ~1.0, got {neg_scores!r}"
    assert neg_scores["Negative"] == max(neg_scores.values()), (
        f"expected Negative to be the dominant component, got {neg_scores!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
