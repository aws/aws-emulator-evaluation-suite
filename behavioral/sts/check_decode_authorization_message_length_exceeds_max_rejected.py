"""decode-authorization-message-length-exceeds-max-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decode-authorization-message-length-exceeds-max-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; raises AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DecodeAuthorizationMessage refuses an EncodedMessage one character past the 10240-char
    maximum with a length ValidationError, distinct from the garbage-content refusal a message
    of the same text at the maximum length still receives."""

    # Client-side parameter validation off, so STS's own input validation answers instead of a
    # local ParamValidationError.
    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))

    # Neighbour control: the same non-genuine text, at the maximum allowed length, passes
    # length validation and is refused only for failing the integrity check — proving the
    # ValidationError below is specifically about the extra character, not about the content.
    at_max = "A" * 10240
    control_code, _ = _refusal(lambda: sts.decode_authorization_message(EncodedMessage=at_max))
    assert control_code == "InvalidAuthorizationMessageException", (
        f"expected a length-10240 message to pass length validation and fail on content, "
        f"got {control_code}"
    )

    over_max = "A" * 10241
    code, message = _refusal(lambda: sts.decode_authorization_message(EncodedMessage=over_max))
    assert code == "ValidationError", (
        f"expected ValidationError for an EncodedMessage one char past the max length, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{over_max}' at 'encodedMessage' failed to satisfy "
        "constraint: Member must have length less than or equal to 10240"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
