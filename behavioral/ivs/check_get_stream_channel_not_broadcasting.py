"""get-stream-channel-not-broadcasting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-stream-channel-not-broadcasting"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetStream on a channel that exists but has never gone live raises ChannelNotBroadcasting,
    a distinct error from the generic ResourceNotFoundException."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(name=name)["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    err = _client_error(lambda: ivs.get_stream(channelArn=arn))
    assert err["Code"] == "ChannelNotBroadcasting", f"expected ChannelNotBroadcasting, got {err!r}"
    expected = f"Channel: {arn} is not currently online"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected GetStream on a non-broadcasting channel to be rejected, but it succeeded "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
