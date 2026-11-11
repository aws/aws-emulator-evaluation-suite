"""batch-detect-dominant-language-partial-failure-isolates-bad-document."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-dominant-language-partial-failure-isolates-bad-document"
GROUP = "batch"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectDominantLanguage with one valid and one oversized document fails as a whole with
    TextSizeLimitExceededException and its exact message (no per-index ErrorList split); the valid
    document alone returns one result at Index 0 with top language "en"."""
    comprehend = ctx.client("comprehend")
    good_text = "Bob lives in Seattle. He is a software engineer at Amazon."
    oversized_text = "x" * 300_000  # far beyond the per-document size limit

    code, message = _error(
        lambda: comprehend.batch_detect_dominant_language(TextList=[good_text, oversized_text])
    )
    assert code == "TextSizeLimitExceededException", code
    expected = (
        "Input text size exceeds limit. Max length of request text allowed is 5000 bytes while "
        f"in this request the text size is {len(oversized_text.encode())} bytes"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the well-formed document alone (no oversized sibling) succeeds, proving
    # the rejection above was driven by the batch containing the bad document, not by anything
    # wrong with the good document itself.
    resp = comprehend.batch_detect_dominant_language(TextList=[good_text])
    assert len(resp["ResultList"]) == 1, resp["ResultList"]
    assert len(resp["ErrorList"]) == 0, resp["ErrorList"]
    good_result = resp["ResultList"][0]
    assert good_result["Index"] == 0, good_result
    assert good_result["Languages"][0]["LanguageCode"] == "en", good_result


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
