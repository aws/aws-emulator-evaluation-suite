"""text-size-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "text-size-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDominantLanguage rejects a document far beyond the documented size
    limit with TextSizeLimitExceededException and returns no language result,
    while a small, valid document still succeeds."""
    comprehend = ctx.client("comprehend")

    # Positive control: a small valid document succeeds.
    ok_resp = comprehend.detect_dominant_language(Text="This is a normal, small piece of text.")
    assert ok_resp["Languages"], "expected the positive control to detect a language"

    # Break the one thing: send a document far larger than the ~100 KB UTF-8 limit.
    oversized_text = "word " * 40000  # ~200 KB
    code, message = _error(lambda: comprehend.detect_dominant_language(Text=oversized_text))
    assert code == "TextSizeLimitExceededException", f"expected TextSizeLimitExceededException, got {code!r}"
    assert message == (
        "Input text size exceeds limit. Max length of request text allowed is 100000 bytes"
        f" while in this request the text size is {len(oversized_text.encode('utf-8'))} bytes"
    ), message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    accepting an oversized document that real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
