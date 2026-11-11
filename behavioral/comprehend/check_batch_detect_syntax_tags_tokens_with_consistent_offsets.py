"""batch-detect-syntax-tags-tokens-with-consistent-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-syntax-tags-tokens-with-consistent-offsets"
GROUP = "batch-semantics"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectSyntax tags parts of speech per document and each token's offsets bound the
    correct source substring in its own document (not a neighbour's)."""
    comprehend = ctx.client("comprehend")
    docs = ["The cat sat on the mat.", "Birds fly south in the winter."]
    resp = comprehend.batch_detect_syntax(TextList=docs, LanguageCode="en")

    assert not resp["ErrorList"], f"expected no errors, got {resp['ErrorList']!r}"
    results = sorted(resp["ResultList"], key=lambda r: r["Index"])
    assert len(results) == 2, f"expected 2 results, got {len(results)}: {results!r}"

    for result in results:
        source = docs[result["Index"]]
        tokens = result["SyntaxTokens"]
        assert tokens, f"expected syntax tokens for document {result['Index']}"
        for tok in tokens:
            begin, end = tok["BeginOffset"], tok["EndOffset"]
            assert source[begin:end] == tok["Text"], (
                f"doc {result['Index']} token offsets [{begin}:{end}] -> {source[begin:end]!r} "
                f"!= reported Text {tok['Text']!r}"
            )

    by_text_0 = {t["Text"].lower(): t for t in results[0]["SyntaxTokens"]}
    tag_0 = by_text_0.get("cat", {}).get("PartOfSpeech", {}).get("Tag")
    assert tag_0 == "NOUN", f"expected 'cat' tagged NOUN in doc 0, got {tag_0!r}: {by_text_0.get('cat')!r}"
    by_text_1 = {t["Text"].lower(): t for t in results[1]["SyntaxTokens"]}
    tag_1 = by_text_1.get("fly", {}).get("PartOfSpeech", {}).get("Tag")
    assert tag_1 == "VERB", f"expected 'fly' tagged VERB in doc 1, got {tag_1!r}: {by_text_1.get('fly')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
