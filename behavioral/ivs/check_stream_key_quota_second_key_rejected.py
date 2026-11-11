"""stream-key-quota-second-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-key-quota-second-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamKey on a channel that holds its auto-created key fails ServiceQuotaExceededException with the
    exact message and leaves that key alone; after it is deleted a new key is created."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-quota-")
    resp = ivs.create_channel(name=name, tags={"purpose": "sim2real"})
    arn = resp["channel"]["arn"]
    original_key_arn = resp["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    error = _error(lambda: ivs.create_stream_key(channelArn=arn))
    assert error["Code"] == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException on a second CreateStreamKey, got {error['Code']!r}"
    )
    assert error["Message"] == "Resource: stream-key quota exceeded limit: 1", repr(error["Message"])

    keys_after_reject = [k["arn"] for k in ivs.list_stream_keys(channelArn=arn)["streamKeys"]]
    assert keys_after_reject == [original_key_arn], (
        f"expected only the original key {original_key_arn!r} after the rejected "
        f"CreateStreamKey, got {keys_after_reject}"
    )

    ivs.delete_stream_key(arn=original_key_arn)
    new_key_arn = ivs.create_stream_key(channelArn=arn)["streamKey"]["arn"]
    keys_after_control = [k["arn"] for k in ivs.list_stream_keys(channelArn=arn)["streamKeys"]]
    assert keys_after_control == [new_key_arn], (
        f"expected only the new key {new_key_arn!r} after freeing the quota slot, "
        f"got {keys_after_control}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
