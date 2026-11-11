"""detect-toxic-content-scores-higher-for-toxic-segment."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-toxic-content-scores-higher-for-toxic-segment"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectToxicContent scores an overtly abusive segment higher than a neutral one, in the same call."""
    comprehend = ctx.client("comprehend")
    segments = [
        {"Text": "I love sunny days and going for long walks in the park with my dog."},
        {"Text": "I will hunt you down and hurt you, you worthless piece of garbage."},
    ]
    resp = comprehend.detect_toxic_content(TextSegments=segments, LanguageCode="en")
    results = resp["ResultList"]
    assert len(results) == 2, f"expected one result per segment, got {results!r}"

    for result in results:
        assert 0.0 <= result["Toxicity"] <= 1.0, result
        for label in result["Labels"]:
            assert 0.0 <= label["Score"] <= 1.0, label

    neutral_score = results[0]["Toxicity"]
    toxic_score = results[1]["Toxicity"]
    assert toxic_score > neutral_score, (
        f"expected the abusive segment to score higher than the neutral one: "
        f"neutral={neutral_score!r} toxic={toxic_score!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
