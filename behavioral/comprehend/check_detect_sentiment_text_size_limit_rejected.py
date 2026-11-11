"""detect-sentiment-text-size-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-sentiment-text-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectSentiment rejects text over the documented 5 KB maximum with
    TextSizeLimitExceededException and returns no Sentiment result, while the identical
    operation on a small document still succeeds."""
    comprehend = ctx.client("comprehend")
    oversized_text = "This product is great. " * 400  # well over 5 KB (5000 bytes) of UTF-8

    code, message = _error(
        lambda: comprehend.detect_sentiment(Text=oversized_text, LanguageCode="en")
    )
    assert code == "TextSizeLimitExceededException", f"expected TextSizeLimitExceededException, got {code!r}"
    expected = (
        "Input text size exceeds limit. Max length of request text allowed is 5000 bytes while "
        f"in this request the text size is {len(oversized_text.encode())} bytes"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical operation on a compliant-sized document succeeds.
    ok_resp = comprehend.detect_sentiment(Text="This product is great.", LanguageCode="en")
    assert ok_resp["Sentiment"] in {"POSITIVE", "NEGATIVE", "NEUTRAL", "MIXED"}, ok_resp


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
