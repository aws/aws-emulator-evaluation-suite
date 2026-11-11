"""create-stream-key-resource-not-found-bad-channel."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stream-key-resource-not-found-bad-channel"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamKey against a channelArn that does not exist raises
    ResourceNotFoundException instead of creating an orphaned stream key,
    while the identical call against a real channel succeeds."""
    ivs = ctx.client("ivs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account}:channel/does-not-exist-0000001"

    error = _client_error(lambda: ivs.create_stream_key(channelArn=bogus_arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a channelArn that was never created, got {error!r}"
    )
    assert error["Message"] == f"Resource: {bogus_arn} not found", (
        f"unexpected CreateStreamKey not-found message: {error['Message']!r}"
    )

    # Positive control: the identical shape of call against a real channel succeeds,
    # so the rejection above is shown to be about the bad channel, not about the
    # account or the operation being blocked outright.
    name = ctx.unique_name("sim2real-ivs-notfound-ctrl-")
    channel = ivs.create_channel(name=name)["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel["arn"]))

    default_keys = ivs.list_stream_keys(channelArn=channel["arn"])["streamKeys"]
    assert len(default_keys) == 1, (
        f"expected the new channel to carry exactly one default stream key, got {len(default_keys)}"
    )
    ivs.delete_stream_key(arn=default_keys[0]["arn"])

    new_key = ivs.create_stream_key(channelArn=channel["arn"])["streamKey"]
    assert new_key["channelArn"] == channel["arn"], (
        f"expected the new stream key bound to {channel['arn']!r}, got {new_key['channelArn']!r}"
    )
    assert new_key["value"], "expected a nonempty stream key value from the positive control"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
