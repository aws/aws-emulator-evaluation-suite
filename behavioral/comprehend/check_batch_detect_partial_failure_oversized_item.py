"""batch-detect-partial-failure-oversized-item."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-partial-failure-oversized-item"
GROUP = "batch-inference"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectSentiment with one valid and one over-5 KB document fails as a whole with
    TextSizeLimitExceededException and its exact message (no per-index ErrorList split); the valid
    document alone returns one result at Index 0 and no errors."""
    comprehend = ctx.client("comprehend")
    oversized = "a" * 6000  # exceeds the ~5 KB per-document limit for sync sentiment analysis
    good_text = "Short valid text for sentiment analysis."

    code, message = _error(
        lambda: comprehend.batch_detect_sentiment(
            TextList=[good_text, oversized], LanguageCode="en"
        )
    )
    assert code == "TextSizeLimitExceededException", code
    expected = (
        "Input text size exceeds limit. Max length of request text allowed is 5000 bytes while "
        f"in this request the text size is {len(oversized.encode())} bytes"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the valid document alone (no oversized sibling) succeeds, proving the
    # whole-batch rejection above was driven by the oversized document, not the good one.
    resp = comprehend.batch_detect_sentiment(TextList=[good_text], LanguageCode="en")
    assert len(resp["ResultList"]) == 1, resp["ResultList"]
    assert len(resp["ErrorList"]) == 0, resp["ErrorList"]
    assert resp["ResultList"][0]["Index"] == 0, resp["ResultList"]


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

