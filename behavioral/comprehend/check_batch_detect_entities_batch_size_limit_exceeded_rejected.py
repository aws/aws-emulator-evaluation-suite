"""batch-detect-entities-batch-size-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-detect-entities-batch-size-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectEntities rejects a batch over the 25-document quota, but a small batch still succeeds."""
    comprehend = ctx.client("comprehend")
    # Batch quota is 25 documents per request.
    # https://docs.aws.amazon.com/comprehend/latest/dg/guidelines-and-limits.html
    too_many = ["A short valid document about Amazon Web Services."] * 26

    code, message = _error(lambda: comprehend.batch_detect_entities(TextList=too_many, LanguageCode="en"))
    assert code == "BatchSizeLimitExceededException", f"unexpected error code: {code!r}"
    expected = "Please use a smaller number of items in a single batch. Maximum batch size is 25."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same operation with a compliant batch size still succeeds.
    resp = comprehend.batch_detect_entities(
        TextList=["Amazon Web Services is based in Seattle.", "Microsoft is based in Redmond."],
        LanguageCode="en",
    )
    assert not resp["ErrorList"], resp["ErrorList"]
    assert len(resp["ResultList"]) == 2, resp["ResultList"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
