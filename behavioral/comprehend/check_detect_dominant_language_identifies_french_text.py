"""detect-dominant-language-identifies-french-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-dominant-language-identifies-french-text"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDominantLanguage identifies clearly-French text as fr and returns scores sorted descending."""
    comprehend = ctx.client("comprehend")
    text = (
        "Le chat noir dort paisiblement sur le tapis rouge pendant que le soleil "
        "brille a travers la fenetre de la cuisine."
    )
    resp = comprehend.detect_dominant_language(Text=text)
    languages = resp["Languages"]
    assert languages, "expected at least one detected language"

    assert languages[0]["LanguageCode"] == "fr", f"expected top language fr, got {languages!r}"
    assert languages[0]["Score"] > 0.7, f"expected high confidence for fr, got {languages[0]!r}"

    # Scores must be sorted in descending order.
    scores = [entry["Score"] for entry in languages]
    assert scores == sorted(scores, reverse=True), f"language scores not sorted descending: {scores!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
