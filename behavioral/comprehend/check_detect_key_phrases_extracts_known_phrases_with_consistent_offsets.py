"""detect-key-phrases-extracts-known-phrases-with-consistent-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-key-phrases-extracts-known-phrases-with-consistent-offsets"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectKeyPhrases finds the salient noun phrases in a documented-example sentence, and
    every returned offset pair slices back to exactly the reported phrase text."""
    comprehend = ctx.client("comprehend")
    text = "Bob lives in Seattle. He is a software engineer at Amazon."

    resp = comprehend.detect_key_phrases(Text=text, LanguageCode="en")
    phrases = resp["KeyPhrases"]
    assert len(phrases) > 0, "expected at least one key phrase"

    for phrase in phrases:
        begin, end = phrase["BeginOffset"], phrase["EndOffset"]
        assert text[begin:end] == phrase["Text"], (
            f"offset [{begin}:{end}] does not slice back to reported text {phrase['Text']!r}"
        )
        assert 0.0 <= phrase["Score"] <= 1.0, f"score out of range: {phrase!r}"

    phrase_texts = {p["Text"] for p in phrases}
    assert "Seattle" in phrase_texts, phrase_texts
    assert "Amazon" in phrase_texts, phrase_texts


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
