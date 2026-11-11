"""detect-sentiment-text-size-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-sentiment-text-size-limit-exceeded-rejected"
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
    """DetectSentiment rejects a document over the 5 KB real-time size quota, but a small document still succeeds."""
    comprehend = ctx.client("comprehend")
    # Real-time DetectSentiment quota is 5 KB per document.
    # https://docs.aws.amazon.com/comprehend/latest/dg/guidelines-and-limits.html
    oversized_text = "x" * 5001

    code, message = _error(lambda: comprehend.detect_sentiment(Text=oversized_text, LanguageCode="en"))
    assert code == "TextSizeLimitExceededException", f"unexpected error code: {code!r}"
    expected = (
        "Input text size exceeds limit. Max length of request text allowed is 5000 bytes while "
        f"in this request the text size is {len(oversized_text.encode())} bytes"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same operation with a compliant document still succeeds.
    resp = comprehend.detect_sentiment(Text="This is a short, valid document.", LanguageCode="en")
    assert resp["Sentiment"] in {"POSITIVE", "NEGATIVE", "NEUTRAL", "MIXED"}, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
