"""detect-dominant-language-english."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-dominant-language-english"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDominantLanguage identifies clearly English text as "en" with high
    confidence and reports the languages ranked by descending score."""
    comprehend = ctx.client("comprehend")
    text = (
        "The weather today is absolutely beautiful and sunny with clear skies "
        "over the mountains and the lake."
    )
    resp = comprehend.detect_dominant_language(Text=text)
    languages = resp["Languages"]
    assert languages, "expected at least one detected language"
    top = languages[0]
    assert top["LanguageCode"] == "en", f"expected top language en, got {top!r}"
    assert top["Score"] > 0.9, f"expected high confidence for en, got {top!r}"
    scores = [lang["Score"] for lang in languages]
    assert scores == sorted(scores, reverse=True), "Languages must be ranked by descending score"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
