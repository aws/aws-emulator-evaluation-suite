"""batch-detect-entities-batch-size-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-detect-entities-batch-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectEntities rejects a TextList with more than 25 documents with
    BatchSizeLimitExceededException -- and rejects it wholesale (no partial ResultList/ErrorList
    is produced) -- while the identical operation with a compliant list still succeeds."""
    comprehend = ctx.client("comprehend")
    too_many = [f"Document number {i} contains some ordinary English text." for i in range(26)]

    code, message = _error(
        lambda: comprehend.batch_detect_entities(TextList=too_many, LanguageCode="en")
    )
    assert code == "BatchSizeLimitExceededException", (
        f"expected BatchSizeLimitExceededException for a 26-document TextList, got {code!r}"
    )
    expected = "Please use a smaller number of items in a single batch. Maximum batch size is 25."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical operation with a compliant-sized list succeeds.
    ok_resp = comprehend.batch_detect_entities(
        TextList=["Bob works at Amazon in Seattle.", "Jane lives in Boston."],
        LanguageCode="en",
    )
    assert len(ok_resp["ResultList"]) == 2, (
        f"expected 2 results for a 2-document TextList, got {ok_resp['ResultList']!r}"
    )
    assert ok_resp["ErrorList"] == [], (
        f"expected no per-item errors for a compliant TextList, got {ok_resp['ErrorList']!r}"
    )


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
