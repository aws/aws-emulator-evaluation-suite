"""batch-detect-dominant-language-preserves-index-mapping."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-dominant-language-preserves-index-mapping"
GROUP = "batch-semantics"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectDominantLanguage maps each ResultList entry back to its original TextList index correctly."""
    comprehend = ctx.client("comprehend")
    texts = [
        "This is a clear and simple sentence written in the English language.",
        "Ceci est une phrase simple et claire ecrite en langue francaise.",
        "Esta es una oracion simple y clara escrita en el idioma espanol.",
    ]
    expected_language_by_index = {0: "en", 1: "fr", 2: "es"}

    resp = comprehend.batch_detect_dominant_language(TextList=texts)
    results = resp["ResultList"]
    assert not resp["ErrorList"], f"expected no errors, got {resp['ErrorList']!r}"
    assert len(results) == 3, results

    for result in results:
        idx = result["Index"]
        top_language = max(result["Languages"], key=lambda lang: lang["Score"])["LanguageCode"]
        assert top_language == expected_language_by_index[idx], (
            f"index {idx} expected {expected_language_by_index[idx]!r}, got {top_language!r} "
            f"(languages={result['Languages']!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
