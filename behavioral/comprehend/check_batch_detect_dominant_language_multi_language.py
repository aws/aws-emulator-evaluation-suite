"""batch-detect-dominant-language-multi-language."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-dominant-language-multi-language"
GROUP = "batch-inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectDominantLanguage returns the right top language for French, Spanish and English documents
    under each document's Index, with each document's Languages sorted by descending Score."""
    comprehend = ctx.client("comprehend")
    text_list = [
        "Bonjour, comment allez-vous aujourd'hui? J'espere que vous passez une bonne journee.",
        "Hola, como estas hoy? Espero que tengas un dia maravilloso y muy feliz.",
        "Hello, how are you today? I hope you are having a wonderful and productive day.",
    ]
    expected_language_by_index = {0: "fr", 1: "es", 2: "en"}

    resp = comprehend.batch_detect_dominant_language(TextList=text_list)
    assert resp["ErrorList"] == [], f"expected no errors, got {resp['ErrorList']!r}"
    results = resp["ResultList"]
    assert len(results) == 3, f"expected 3 results, got {len(results)}: {results!r}"

    top_language_by_index = {}
    for result in results:
        idx = result["Index"]
        languages = result["Languages"]
        assert languages, f"index {idx}: expected at least one detected language"
        scores = [lang["Score"] for lang in languages]
        assert scores == sorted(scores, reverse=True), (
            f"index {idx}: Languages not sorted descending by Score: {languages!r}"
        )
        top_language_by_index[idx] = languages[0]["LanguageCode"]

    for idx, expected in expected_language_by_index.items():
        assert top_language_by_index[idx] == expected, (
            f"index {idx}: expected top language {expected!r}, got "
            f"{top_language_by_index[idx]!r} (all results: {results!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
