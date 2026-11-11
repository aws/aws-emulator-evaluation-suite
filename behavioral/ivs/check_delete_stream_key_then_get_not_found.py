"""delete-stream-key-then-get-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-stream-key-then-get-not-found"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteStreamKey, GetStreamKey and a second delete fail ResourceNotFoundException with the exact message
    and the key leaves ListStreamKeys, while another channel's stream key stays readable."""
    ivs = ctx.client("ivs")

    check_tags = {"sim2real": CHECK}

    kept_name = ctx.unique_name("sim2real-ivs-keep-")
    kept = ivs.create_channel(name=kept_name, tags=check_tags)
    kept_channel_arn = kept["channel"]["arn"]
    kept_key_arn = kept["streamKey"]["arn"]
    kept_key_value = kept["streamKey"]["value"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=kept_channel_arn))

    victim_name = ctx.unique_name("sim2real-ivs-victim-")
    victim = ivs.create_channel(name=victim_name, tags=check_tags)
    victim_channel_arn = victim["channel"]["arn"]
    victim_key_arn = victim["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=victim_channel_arn))

    ivs.delete_stream_key(arn=victim_key_arn)

    error = _client_error(lambda: ivs.get_stream_key(arn=victim_key_arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    assert error["Message"] == f"Resource: {victim_key_arn} not found", (
        f"unexpected GetStreamKey not-found message: {error['Message']!r}"
    )

    remaining = ivs.list_stream_keys(channelArn=victim_channel_arn)["streamKeys"]
    assert remaining == [], f"expected no stream keys left on the victim channel, got {remaining!r}"

    # Mutation on the dead id: a second delete of the same key must not resurrect it.
    second = _client_error(lambda: ivs.delete_stream_key(arn=victim_key_arn))
    assert second["Code"] == "ResourceNotFoundException", (
        f"expected a double-delete of the same key to also 404, got {second!r}"
    )
    assert second["Message"] == f"Resource: {victim_key_arn} not found", (
        f"unexpected DeleteStreamKey not-found message: {second['Message']!r}"
    )

    # Positive control: the untouched channel's key is still fully readable.
    still_there = ivs.get_stream_key(arn=kept_key_arn)["streamKey"]
    assert still_there["arn"] == kept_key_arn, still_there
    assert still_there["value"] == kept_key_value, still_there


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
