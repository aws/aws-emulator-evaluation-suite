"""batch-detect-sentiment-index-alignment."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-sentiment-index-alignment"
GROUP = "batch-inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectSentiment maps each ResultList entry back to the correct Index
    of its originating TextList item, and each item's sentiment matches its
    unambiguous polarity."""
    comprehend = ctx.client("comprehend")
    text_list = [
        "I love sunny days, they make me feel so happy and alive.",
        "I hate rainy days and everything about how miserable they make me feel.",
        "The meeting starts at noon in conference room three.",
    ]
    resp = comprehend.batch_detect_sentiment(TextList=text_list, LanguageCode="en")
    assert resp["ErrorList"] == [], resp["ErrorList"]
    results = {r["Index"]: r for r in resp["ResultList"]}
    assert set(results.keys()) == {0, 1, 2}, results
    assert results[0]["Sentiment"] == "POSITIVE", results[0]
    assert results[1]["Sentiment"] == "NEGATIVE", results[1]
    assert results[2]["Sentiment"] == "NEUTRAL", results[2]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
