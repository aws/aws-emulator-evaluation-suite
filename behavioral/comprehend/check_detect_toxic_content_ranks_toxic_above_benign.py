"""detect-toxic-content-ranks-toxic-above-benign."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-toxic-content-ranks-toxic-above-benign"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectToxicContent scores an abusive segment above a benign one in the same batch, with scores in
    [0, 1] and one result per segment in request order, and still does so with the segments swapped."""
    comprehend = ctx.client("comprehend")
    benign = "I love spending time with my family and friends on the weekend."
    toxic = "You are a worthless piece of garbage and everyone hates you, idiot."

    def toxicity_scores(text_segments):
        resp = comprehend.detect_toxic_content(TextSegments=text_segments, LanguageCode="en")
        results = resp["ResultList"]
        assert len(results) == len(text_segments), (
            f"expected {len(text_segments)} results, got {len(results)}: {results!r}"
        )
        for result in results:
            assert 0.0 <= result["Toxicity"] <= 1.0, f"Toxicity out of [0,1]: {result!r}"
            for label in result.get("Labels", []):
                assert 0.0 <= label["Score"] <= 1.0, f"label score out of [0,1]: {label!r}"
        return [result["Toxicity"] for result in results]

    benign_score, toxic_score = toxicity_scores([{"Text": benign}, {"Text": toxic}])
    assert toxic_score > benign_score, (
        f"expected the segment at position 1 (toxic) to score higher than position 0 (benign): "
        f"benign={benign_score!r} toxic={toxic_score!r}"
    )

    toxic_score_swapped, benign_score_swapped = toxicity_scores([{"Text": toxic}, {"Text": benign}])
    assert toxic_score_swapped > benign_score_swapped, (
        f"ranking must follow content, not batch position — with order swapped, expected the "
        f"segment at position 0 (toxic) to still score higher than position 1 (benign): "
        f"toxic={toxic_score_swapped!r} benign={benign_score_swapped!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
