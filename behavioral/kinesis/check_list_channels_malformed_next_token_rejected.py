"""list-channels-malformed-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channels-malformed-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _client_error(fn):
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannels with a malformed NextToken fails with ValidationException and the message "Invalid
    NextToken." (not ExpiredNextTokenException), while ListChannels without a token succeeds before and after."""
    kinesis = ctx.client("kinesis")

    # Positive control: a plain, un-paginated ListChannels succeeds and returns
    # the documented shape.
    resp = kinesis.list_channels(MaxResults=1)
    assert "ChannelSummaries" in resp

    # A syntactically-invalid NextToken exercises the token-validation path
    # without needing to wait out the real ~300s TTL or provision channels.
    bogus_token = "sim2real-not-a-real-next-token-deadbeef"
    error = _client_error(lambda: kinesis.list_channels(NextToken=bogus_token))
    code = error.get("Code")
    assert code != "ExpiredNextTokenException", (
        "a syntactically-invalid token must not be classified the same as a "
        f"well-formed-but-expired one, got {code!r}"
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed NextToken, got {code!r}"
    )
    expected_message = "Invalid NextToken."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # The API itself is still healthy afterward — rejection is specific to the
    # bad token, not a side effect of probing it.
    control = kinesis.list_channels(MaxResults=1)
    assert "ChannelSummaries" in control


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

