"""stop-stream-channel-not-broadcasting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stop-stream-channel-not-broadcasting"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopStream on a channel that has no active stream raises ChannelNotBroadcasting, and
    an independent read (GetStream, a different operation) agrees the channel is not live."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    expected = f"Channel: {arn} is not currently online"
    err = _client_error(lambda: ivs.stop_stream(channelArn=arn))
    assert err["Code"] == "ChannelNotBroadcasting", (
        f"StopStream on a channel that never went live should raise ChannelNotBroadcasting, "
        f"got {err!r}"
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # independent read at the destination, through a different operation than the one under test
    read_err = _client_error(lambda: ivs.get_stream(channelArn=arn))
    assert read_err["Code"] == "ChannelNotBroadcasting", (
        f"GetStream should independently confirm the channel has no active stream, got {read_err!r}"
    )
    assert read_err["Message"] == expected, (
        f"expected message {expected!r}, got {read_err['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
