"""batch-detect-sentiment-preserves-index-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-sentiment-preserves-index-order"
GROUP = "batch"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectSentiment maps each ResultList entry back to its originating TextList index,
    and each entry's Sentiment matches the polarity of its own document (not some other one)."""
    comprehend = ctx.client("comprehend")
    texts = [
        "I love this product, it's absolutely wonderful and exceeded expectations!",
        "I hate this, it's absolutely terrible and broke immediately after purchase.",
    ]

    resp = comprehend.batch_detect_sentiment(TextList=texts, LanguageCode="en")
    assert resp["ErrorList"] == [], resp["ErrorList"]
    results = sorted(resp["ResultList"], key=lambda r: r["Index"])
    assert [r["Index"] for r in results] == [0, 1], results

    assert results[0]["Sentiment"] == "POSITIVE", results[0]
    assert results[1]["Sentiment"] == "NEGATIVE", results[1]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
