"""batch-detect-key-phrases-consistent-for-duplicate-inputs."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-key-phrases-consistent-for-duplicate-inputs"
GROUP = "batch-semantics"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectKeyPhrases returns identical KeyPhrases for two byte-identical documents in one request."""
    comprehend = ctx.client("comprehend")
    text = "Amazon Comprehend uses natural language processing to extract insights from text."
    resp = comprehend.batch_detect_key_phrases(TextList=[text, text], LanguageCode="en")

    assert not resp["ErrorList"], f"expected no errors, got {resp['ErrorList']!r}"
    results = sorted(resp["ResultList"], key=lambda r: r["Index"])
    assert len(results) == 2, results

    def normalize(phrases):
        return sorted((p["Text"], p["BeginOffset"], p["EndOffset"]) for p in phrases)

    first = normalize(results[0]["KeyPhrases"])
    second = normalize(results[1]["KeyPhrases"])
    assert first, "expected at least one key phrase"
    assert first == second, (
        f"identical input documents produced different key phrases: {first!r} vs {second!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
