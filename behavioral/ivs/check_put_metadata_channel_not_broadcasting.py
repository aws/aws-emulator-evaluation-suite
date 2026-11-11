"""put-metadata-channel-not-broadcasting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-metadata-channel-not-broadcasting"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetadata on a channel that is not currently live raises ChannelNotBroadcasting; timed
    metadata cannot be injected into a stream that does not exist."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    error = _error(lambda: ivs.put_metadata(channelArn=arn, metadata="sim2real-marker"))
    assert error["Code"] == "ChannelNotBroadcasting", f"expected ChannelNotBroadcasting, got {error['Code']!r}"
    assert error["Message"] == f"Channel: {arn} is not currently online", repr(error["Message"])


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
