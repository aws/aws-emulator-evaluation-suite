"""detect-syntax-tags-noun-and-verb."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-syntax-tags-noun-and-verb"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSyntax tags 'cat' as a NOUN and 'sat' as a VERB in a simple English sentence."""
    comprehend = ctx.client("comprehend")
    text = "The cat sat on the mat."
    resp = comprehend.detect_syntax(Text=text, LanguageCode="en")
    tokens = resp["SyntaxTokens"]
    assert tokens, "expected syntax tokens"

    by_text = {tok["Text"].lower(): tok for tok in tokens}
    assert "cat" in by_text, f"expected token 'cat' among {[t['Text'] for t in tokens]!r}"
    assert "sat" in by_text, f"expected token 'sat' among {[t['Text'] for t in tokens]!r}"

    assert by_text["cat"]["PartOfSpeech"]["Tag"] == "NOUN", by_text["cat"]
    assert by_text["sat"]["PartOfSpeech"]["Tag"] == "VERB", by_text["sat"]

    for tok in tokens:
        begin, end = tok["BeginOffset"], tok["EndOffset"]
        assert text[begin:end] == tok["Text"], f"token offsets mismatch for {tok!r}"

    # Full per-token shape, not just the two named lookups: a stub that answers
    # only "cat"/"sat" from a bag-of-words table cannot fake token count, id
    # order, non-overlapping offsets or the whole sentence's tag sequence.
    assert len(tokens) == 7, f"expected 7 tokens for {text!r}, got {[t['Text'] for t in tokens]!r}"
    token_ids = [tok["TokenId"] for tok in tokens]
    assert token_ids == list(range(1, 8)), f"expected TokenId 1..7 in order, got {token_ids!r}"
    for prev_tok, next_tok in zip(tokens, tokens[1:]):
        assert prev_tok["EndOffset"] <= next_tok["BeginOffset"], (
            f"token offsets overlap or go backwards: {prev_tok!r} then {next_tok!r}"
        )
    tags_in_order = [tok["PartOfSpeech"]["Tag"] for tok in tokens]
    expected_tags = ["DET", "NOUN", "VERB", "ADP", "DET", "NOUN", "PUNCT"]
    assert tags_in_order == expected_tags, (
        f"expected tag sequence {expected_tags!r} for {text!r}, got {tags_in_order!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
