"""create-stream-key-channel-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stream-key-channel-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamKey rejects a well-formed but nonexistent channelArn, while the
    identical call against a real channel (with no existing key) succeeds."""
    ivs = ctx.client("ivs")

    # A deleted channel gives us a syntactically valid, guaranteed-nonexistent ARN
    # in the right account/region/partition -- exercising ResourceNotFoundException
    # rather than a pattern-validation error.
    ghost_name = ctx.unique_name("sim2real-ivs-ghost-")
    ghost = ivs.create_channel(name=ghost_name)["channel"]
    ghost_arn = ghost["arn"]
    ivs.delete_channel(arn=ghost_arn)

    # Independent read (GetChannel, not the CreateStreamKey we are about to test) proves the
    # channel is actually gone, before we lean on that absence for the real assertion.
    read_error = _client_error(lambda: ivs.get_channel(arn=ghost_arn))
    assert read_error["Code"] == "ResourceNotFoundException", (
        f"GetChannel on the deleted channel returned {read_error!r}, expected "
        f"ResourceNotFoundException"
    )
    assert read_error["Message"] == f"Resource: {ghost_arn} not found", (
        f"unexpected GetChannel not-found message: {read_error['Message']!r}"
    )

    error = _client_error(lambda: ivs.create_stream_key(channelArn=ghost_arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"CreateStreamKey against a deleted channel returned {error!r}, expected "
        f"ResourceNotFoundException"
    )
    assert error["Message"] == f"Resource: {ghost_arn} not found", (
        f"unexpected CreateStreamKey not-found message: {error['Message']!r}"
    )

    # Positive control: a live channel with its default key removed can get a new one.
    live_name = ctx.unique_name("sim2real-ivs-live-")
    live = ivs.create_channel(name=live_name)["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=live["arn"]))
    keys = ivs.list_stream_keys(channelArn=live["arn"])["streamKeys"]
    assert len(keys) == 1, f"a freshly created channel had {len(keys)} stream keys, expected 1"
    ivs.delete_stream_key(arn=keys[0]["arn"])

    new_key = ivs.create_stream_key(channelArn=live["arn"])["streamKey"]

    # Terminal read is independent of the CreateStreamKey call that produced the key: GetStreamKey
    # fetches it back through a different operation, at the destination.
    fetched = ivs.get_stream_key(arn=new_key["arn"])["streamKey"]
    assert fetched["channelArn"] == live["arn"], (
        f"GetStreamKey reported channelArn {fetched['channelArn']!r}, expected {live['arn']!r}"
    )
    assert fetched["value"] == new_key["value"], (
        "GetStreamKey returned a different key value than CreateStreamKey reported for the same "
        "ARN"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
