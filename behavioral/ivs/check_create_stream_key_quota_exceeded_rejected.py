"""create-stream-key-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stream-key-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamKey on a channel that holds its one auto-created key fails ServiceQuotaExceededException with
    the exact message and leaves the key set unchanged; after that key is deleted a new one is created."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    created = ivs.create_channel(name=name, tags={"purpose": "sim2real"})
    channel_arn = created["channel"]["arn"]
    auto_key_arn = created["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))

    error = _client_error(lambda: ivs.create_stream_key(channelArn=channel_arn))
    assert error["Code"] == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException, got {error!r}"
    )
    assert error["Message"] == "Resource: stream-key quota exceeded limit: 1", (
        f"unexpected stream-key quota message: {error['Message']!r}"
    )

    # effect absent: still exactly the one auto-created key
    keys = ivs.list_stream_keys(channelArn=channel_arn)["streamKeys"]
    assert [k["arn"] for k in keys] == [auto_key_arn], (
        f"expected only {auto_key_arn}, got {[k['arn'] for k in keys]}"
    )

    # positive control: freeing the slot lets a new stream key be created
    ivs.delete_stream_key(arn=auto_key_arn)
    new_key_arn = ivs.create_stream_key(channelArn=channel_arn)["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stream_key(arn=new_key_arn))
    assert new_key_arn != auto_key_arn, "expected a freshly minted key arn, not the deleted one"

    # terminal read: independent of the create_stream_key response that minted the new key
    keys_after_control = ivs.list_stream_keys(channelArn=channel_arn)["streamKeys"]
    assert [k["arn"] for k in keys_after_control] == [new_key_arn], (
        f"expected only {new_key_arn} at the destination, got "
        f"{[k['arn'] for k in keys_after_control]}"
    )


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
