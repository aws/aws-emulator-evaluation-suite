"""detect-key-phrases-content."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-key-phrases-content"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectKeyPhrases returns non-empty, scored key phrases whose offsets index
    back correctly into the source text."""
    comprehend = ctx.client("comprehend")
    text = "The quick brown fox jumps over the lazy dog in the green forest."
    resp = comprehend.detect_key_phrases(Text=text, LanguageCode="en")
    phrases = resp["KeyPhrases"]
    assert len(phrases) > 0, "expected at least one key phrase"
    for phrase in phrases:
        begin, end = phrase["BeginOffset"], phrase["EndOffset"]
        assert text[begin:end] == phrase["Text"], (
            f"offset [{begin}:{end}] -> {text[begin:end]!r} does not match reported Text {phrase['Text']!r}"
        )
        assert 0.0 <= phrase["Score"] <= 1.0, f"score out of range: {phrase!r}"
    joined = " ".join(p["Text"].lower() for p in phrases)
    assert "fox" in joined or "forest" in joined, f"expected a fox- or forest-related key phrase, got {phrases!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
