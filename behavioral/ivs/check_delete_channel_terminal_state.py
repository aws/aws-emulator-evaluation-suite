"""delete-channel-terminal-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-channel-terminal-state"
GROUP = "state"
SERVICES = ["ivs"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannel is a terminal transition: the channel 404s afterward, a mutation
    against the same dead ARN also 404s, and an unrelated channel created in the same
    run remains readable (positive control)."""
    ivs = ctx.client("ivs")
    channel_tags = {"purpose": "sim2real"}
    kept_name = ctx.unique_name("sim2real-ivs-keep-")
    kept = ivs.create_channel(name=kept_name, tags=channel_tags)["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=kept["arn"]))

    victim_name = ctx.unique_name("sim2real-ivs-victim-")
    victim = ivs.create_channel(name=victim_name, tags=channel_tags)["channel"]
    victim_arn = victim["arn"]

    ivs.delete_channel(arn=victim_arn)

    error = _client_error(lambda: ivs.get_channel(arn=victim_arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"GetChannel on a deleted channel must raise ResourceNotFoundException, got {error!r}"
    )
    assert error["Message"] == f"Resource: {victim_arn} not found", (
        f"unexpected GetChannel not-found message: {error['Message']!r}"
    )

    # A mutation against the same dead ARN must also 404, not silently no-op.
    update_error = _client_error(lambda: ivs.update_channel(arn=victim_arn, name=victim_name))
    assert update_error["Code"] == "ResourceNotFoundException", (
        f"UpdateChannel on a deleted channel must raise ResourceNotFoundException, got {update_error!r}"
    )
    assert update_error["Message"] == f"Resource: {victim_arn} not found", (
        f"unexpected UpdateChannel not-found message: {update_error['Message']!r}"
    )

    # Effect absent: the deleted channel no longer shows up when filtered by name.
    remaining = ivs.list_channels(filterByName=victim_name)["channels"]
    assert remaining == [], f"deleted channel {victim_name!r} still listed: {remaining!r}"

    # Positive control: the untouched channel is still fully readable.
    still_there = ivs.get_channel(arn=kept["arn"])["channel"]
    assert still_there["arn"] == kept["arn"], (
        f"expected kept channel arn {kept['arn']!r}, got {still_there['arn']!r}"
    )
    assert still_there["name"] == kept_name, (
        f"expected kept channel name {kept_name!r}, got {still_there['name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
