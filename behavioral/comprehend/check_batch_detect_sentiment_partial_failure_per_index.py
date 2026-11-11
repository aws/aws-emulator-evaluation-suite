"""batch-detect-sentiment-partial-failure-per-index."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-sentiment-partial-failure-per-index"
GROUP = "batch-semantics"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectSentiment with one valid and one over-5 KB document fails as a whole with
    TextSizeLimitExceededException and its exact message (no per-index ErrorList split); the valid
    document alone returns one result at Index 0 and no errors."""
    comprehend = ctx.client("comprehend")
    # Real-time single-document quota is 5 KB; this document intentionally exceeds it.
    # https://docs.aws.amazon.com/comprehend/latest/dg/guidelines-and-limits.html
    oversized = "b" * 5001
    good_text = "This is a short and perfectly valid document."

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

    # Positive control: the well-formed document alone (no oversized sibling) succeeds, proving
    # the whole-batch rejection above was driven by the oversized document, not the good one.
    resp = comprehend.batch_detect_sentiment(TextList=[good_text], LanguageCode="en")
    assert len(resp["ResultList"]) == 1, resp["ResultList"]
    assert len(resp["ErrorList"]) == 0, resp["ErrorList"]
    result = resp["ResultList"][0]
    assert result["Index"] == 0, result
    assert result["Sentiment"] in {"POSITIVE", "NEGATIVE", "NEUTRAL", "MIXED"}, result


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

