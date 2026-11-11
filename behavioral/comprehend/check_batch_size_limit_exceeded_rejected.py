"""batch-size-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-size-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDetectDominantLanguage rejects a request with more than 25 documents
    with BatchSizeLimitExceededException and performs no analysis at all, while
    the identical operation on a compliant batch still succeeds."""
    comprehend = ctx.client("comprehend")

    # Positive control: a valid, well-under-limit batch succeeds.
    ok_resp = comprehend.batch_detect_dominant_language(
        TextList=["Hello there, how are you today?", "Bonjour, comment allez-vous?"]
    )
    assert len(ok_resp["ResultList"]) == 2, f"expected 2 results, got {ok_resp['ResultList']!r}"
    assert ok_resp["ErrorList"] == [], f"expected no per-document errors, got {ok_resp['ErrorList']!r}"

    # Break the one thing: exceed the 25-document batch limit.
    oversized_batch = [f"Document number {i} for language analysis." for i in range(26)]
    code, message = _error(lambda: comprehend.batch_detect_dominant_language(TextList=oversized_batch))
    assert code == "BatchSizeLimitExceededException", code
    expected = "Please use a smaller number of items in a single batch. Maximum batch size is 25."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
