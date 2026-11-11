"""stream-key-rotation-changes-value."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stream-key-rotation-changes-value"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a channel's stream key and creating a new one issues a fresh secret value, and
    the deleted key is terminal, not just superseded."""
    ivs = ctx.client("ivs")
    created = ivs.create_channel(
        name=ctx.unique_name("sim2real-ivs-rot-"), tags={"purpose": "sim2real"}
    )
    channel_arn = created["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))
    original_key = created["streamKey"]
    original_value = original_key["value"]
    assert original_value, "create_channel's auto-created stream key had an empty value"

    ivs.delete_stream_key(arn=original_key["arn"])

    error = _error(lambda: ivs.get_stream_key(arn=original_key["arn"]))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted original key, got {error['Code']!r}"
    )
    assert error["Message"] == f"Resource: {original_key['arn']} not found", repr(error["Message"])

    rotated_key = ivs.create_stream_key(
        channelArn=channel_arn, tags={"purpose": "sim2real"}
    )["streamKey"]
    ctx.on_cleanup(lambda: ivs.delete_stream_key(arn=rotated_key["arn"]))
    rotated_value = rotated_key["value"]
    assert rotated_value, "create_stream_key returned an empty value for the rotated key"

    assert rotated_value != original_value, (
        f"rotated key value {rotated_value!r} matches the deleted original {original_value!r}"
    )
    assert rotated_key["arn"] != original_key["arn"], (
        "rotated key reused the deleted original key's arn"
    )

    # GetStreamKey on the new key must return the same rotated value, not the stale one.
    refetched_value = ivs.get_stream_key(arn=rotated_key["arn"])["streamKey"]["value"]
    assert refetched_value == rotated_value, (
        f"GetStreamKey on the rotated key returned {refetched_value!r}, expected {rotated_value!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError("expected ClientError reading the deleted stream key, call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
