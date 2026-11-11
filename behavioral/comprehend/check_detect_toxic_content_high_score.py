"""detect-toxic-content-high-score."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-toxic-content-high-score"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectToxicContent scores an overtly hostile, threatening text segment as
    highly toxic while leaving well-formed structural fields on the result."""
    comprehend = ctx.client("comprehend")
    segments = [
        {
            "Text": (
                "I will find you and hurt you badly, you worthless piece of garbage, "
                "and you deserve every bit of pain coming your way."
            )
        }
    ]
    resp = comprehend.detect_toxic_content(TextSegments=segments, LanguageCode="en")
    results = resp["ResultList"]
    assert len(results) == 1, f"expected one result per segment, got {results!r}"
    result = results[0]
    assert 0.0 <= result["Toxicity"] <= 1.0, f"Toxicity out of [0,1]: {result['Toxicity']!r}"
    assert result["Toxicity"] > 0.5, f"expected high toxicity score, got {result['Toxicity']}"
    assert result["Labels"], "expected at least one toxicity label breakdown"
    for label in result["Labels"]:
        assert 0.0 <= label["Score"] <= 1.0, f"label {label['Name']!r} score out of [0,1]: {label['Score']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
