"""detect-dominant-language-ranks-english-highest."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-dominant-language-ranks-english-highest"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDominantLanguage on a mostly English text with short greetings in other languages returns at
    least two candidates, "en" first with Score above 0.5, sorted by descending Score."""
    comprehend = ctx.client("comprehend")
    text = "Hello 你好 Bonjour Hola Ciao Guten Tag Namaste. I am Bob, a software engineer in Seattle."

    resp = comprehend.detect_dominant_language(Text=text)
    languages = resp["Languages"]
    assert len(languages) >= 2, f"expected multiple ranked candidates, got {languages!r}"

    assert languages[0]["LanguageCode"] == "en", languages
    assert languages[0]["Score"] > 0.5, languages

    scores = [lang["Score"] for lang in languages]
    assert scores == sorted(scores, reverse=True), f"Languages not sorted descending: {scores}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
