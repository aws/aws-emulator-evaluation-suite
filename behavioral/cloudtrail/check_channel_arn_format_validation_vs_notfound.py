"""channel-arn-format-validation-vs-notfound."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-arn-format-validation-vs-notfound"
GROUP = "state-machine"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With ListChannels healthy, GetChannel on a malformed identifier fails with ChannelARNInvalidException
    and a well-formed never-created channel ARN with ChannelNotFoundException, each with AWS's exact
    message: malformed and missing channels are distinct error classes."""
    ct = ctx.client("cloudtrail")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: the channel surface itself is reachable, not blanket-denied.
    ct.list_channels()

    malformed_channel = "not-a-real-cloudtrail-channel-identifier"
    malformed_code, malformed_message = _error(lambda: ct.get_channel(Channel=malformed_channel))
    assert malformed_code == "ChannelARNInvalidException", (
        f"expected GetChannel on a malformed identifier to fail with ChannelARNInvalidException, "
        f"got {malformed_code!r}"
    )
    assert malformed_message == f"The format of the channel ARN {malformed_channel} is not valid.", malformed_message

    wellformed_missing_channel = (
        f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/"
        "55555555-5555-5555-5555-555555555555"
    )
    notfound_code, notfound_message = _error(lambda: ct.get_channel(Channel=wellformed_missing_channel))
    assert notfound_code == "ChannelNotFoundException", (
        f"expected GetChannel on a well-formed but never-created channel ARN to fail with "
        f"ChannelNotFoundException, got {notfound_code!r}"
    )
    assert notfound_message == f"The channel {wellformed_missing_channel} was not found.", notfound_message

    assert malformed_code != notfound_code, (
        "ARN-shape validation and not-found must be distinct error classes, both resolved to "
        f"{malformed_code!r}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses must fail as an unexpected success,
    not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
