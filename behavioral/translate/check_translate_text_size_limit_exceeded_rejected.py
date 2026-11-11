"""translate-text-size-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "translate-text-size-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["translate"]


def _client_error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects text over the size limit, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslateText rejects input text over the 10,000 character synchronous limit."""
    translate = ctx.client("translate")
    too_long = "a" * 10001

    code, message = _client_error(
        lambda: translate.translate_text(
            Text=too_long,
            SourceLanguageCode="en",
            TargetLanguageCode="es",
        )
    )
    assert code == "TextSizeLimitExceededException", (
        f"expected TextSizeLimitExceededException for 10001-char input, got {code!r}"
    )
    expected = (
        "Input text size exceeds limit. Max length of request text allowed is 10000 bytes "
        f"while in this request the text size is {len(too_long.encode())} bytes"
    )
    assert message == expected, f"expected size-limit message {expected!r}, got {message!r}"

    # positive control: text within the limit succeeds
    resp = translate.translate_text(
        Text="a" * 100,
        SourceLanguageCode="en",
        TargetLanguageCode="es",
    )
    assert len(resp["TranslatedText"]) > 0, (
        f"expected a non-empty TranslatedText for in-limit input, got {resp['TranslatedText']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
