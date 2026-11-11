"""detect-syntax-part-of-speech."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-syntax-part-of-speech"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSyntax tags "sat" as a VERB and "cat"/"mat" as NOUNs, with each
    token's offsets indexing back to the exact word in the source text."""
    comprehend = ctx.client("comprehend")
    text = "The cat sat quietly on the mat."
    resp = comprehend.detect_syntax(Text=text, LanguageCode="en")
    tokens = resp["SyntaxTokens"]
    assert tokens, "expected syntax tokens"

    for tok in tokens:
        begin, end = tok["BeginOffset"], tok["EndOffset"]
        assert text[begin:end] == tok["Text"], (
            f"offsets [{begin}:{end}] -> {text[begin:end]!r} != reported Text {tok['Text']!r}"
        )

    by_text = {tok["Text"].lower(): tok["PartOfSpeech"]["Tag"] for tok in tokens}
    assert by_text.get("sat") == "VERB", by_text
    assert by_text.get("cat") == "NOUN", by_text
    assert by_text.get("mat") == "NOUN", by_text


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
