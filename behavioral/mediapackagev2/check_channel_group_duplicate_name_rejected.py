"""channel-group-duplicate-name-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "channel-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateChannelGroup for an existing name fails ConflictException RESOURCE_ALREADY_EXISTS with
    the exact message and leaves the original group's Arn and EgressDomain unchanged, while a group with a
    different name is created."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-dup-")
    first = mp.create_channel_group(
        ChannelGroupName=group_name, ClientToken="token-one", Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    err = _client_error(
        lambda: mp.create_channel_group(ChannelGroupName=group_name, ClientToken="token-two")
    )
    code = err.response["Error"]["Code"]
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected_message = (
        "MediaPackage can't create the resource you requested because a resource with that "
        "name already exists. Verify the name of the resource and then try again"
    )
    assert err.response["Error"]["Message"] == expected_message, err.response
    conflict_type = err.response.get("ConflictExceptionType")
    assert conflict_type == "RESOURCE_ALREADY_EXISTS", (
        f"expected ConflictExceptionType RESOURCE_ALREADY_EXISTS, got {conflict_type!r}"
    )

    # effect absent: the original group is unchanged
    still = mp.get_channel_group(ChannelGroupName=group_name)
    assert still["Arn"] == first["Arn"], f"Arn changed: {first['Arn']!r} -> {still['Arn']!r}"
    assert still["EgressDomain"] == first["EgressDomain"], (
        f"EgressDomain changed: {first['EgressDomain']!r} -> {still['EgressDomain']!r}"
    )

    # positive control: a different name succeeds
    other_name = ctx.unique_name("sim2real-mpv2-cg-other-")
    mp.create_channel_group(ChannelGroupName=other_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=other_name))
    mp.get_channel_group(ChannelGroupName=other_name)


def _client_error(fn: Callable[[], Any]) -> Any:
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a duplicate-name create that real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(
        f"expected duplicate-name CreateChannelGroup to fail, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
