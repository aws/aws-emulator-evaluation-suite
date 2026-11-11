"""detect-key-phrases-extracts-multiword-phrase."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-key-phrases-extracts-multiword-phrase"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectKeyPhrases extracts a multi-word noun phrase as a single KeyPhrase (not two
    single-word phrases concatenated by chance), and every offset exactly bounds its Text."""
    comprehend = ctx.client("comprehend")
    text = "The quick brown fox jumps over the lazy dog in the sunny park."
    resp = comprehend.detect_key_phrases(Text=text, LanguageCode="en")
    phrases = resp["KeyPhrases"]
    assert phrases, "expected at least one key phrase"

    for phrase in phrases:
        begin, end = phrase["BeginOffset"], phrase["EndOffset"]
        substring = text[begin:end]
        assert substring == phrase["Text"], (
            f"phrase offsets [{begin}:{end}] -> {substring!r} do not match reported Text {phrase['Text']!r}"
        )
        assert 0.0 <= phrase["Score"] <= 1.0, f"score out of range: {phrase!r}"

    multiword = [p for p in phrases if " " in p["Text"].strip()]
    assert multiword, f"expected at least one multi-word key phrase, got {phrases!r}"
    assert any("fox" in p["Text"].lower() for p in multiword), (
        f"expected a multi-word key phrase mentioning the fox, got {[p['Text'] for p in multiword]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
