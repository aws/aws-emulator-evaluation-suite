"""detect-dominant-language-below-documented-minimum-still-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-dominant-language-below-documented-minimum-still-succeeds"
GROUP = "error-semantics"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDominantLanguage accepts text shorter than the 20 characters the prose documents (the model's
    minimum length is 1) and returns at least one language, while a longer English text ranks "en" first."""
    comprehend = ctx.client("comprehend")

    # "hi" is 2 characters -- well under the documented 20-char minimum -- yet the real service
    # accepts it and returns a scored language list, not an error.
    resp = comprehend.detect_dominant_language(Text="hi")
    assert "Languages" in resp and len(resp["Languages"]) > 0, resp

    # Positive control: a long-enough document of the same shape also succeeds.
    long_resp = comprehend.detect_dominant_language(
        Text="Bob lives in Seattle. He is a software engineer at Amazon."
    )
    assert long_resp["Languages"][0]["LanguageCode"] == "en", long_resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

